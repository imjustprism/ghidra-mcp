package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.app.script.GhidraState;
import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.DebuggerTargetService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.TraceRmiLauncherService;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.task.TaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.Http;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.Bufs;
import io.github.imjustprism.ghidra.mcp.util.Live;
import io.github.imjustprism.ghidra.mcp.util.LiveBases;
import io.github.imjustprism.ghidra.mcp.util.Lua;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.PointerPath;
import io.github.imjustprism.ghidra.mcp.util.ProcessMemory;
import io.github.imjustprism.ghidra.mcp.util.ProcessResolver;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.ScanValues;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public final class DebuggerHandlers {

    private static final String NO_SESSION =
            "No live debug session. In Ghidra: Debugger -> Launch or attach a "
                    + "target (e.g. local-dbgeng, attach by PID), then retry.";

    private static final String NO_DEBUGGER =
            "Debugger services not loaded in this Ghidra tool. Open the program in "
                    + "the Debugger tool (or add the Debugger plugins to this tool), "
                    + "then launch/attach a target.";

    private static final String NO_SESSION_OR_ATTACH =
            "No live session. Use live_attach (connector-less OpenProcess — works without dbgeng) "
                    + "or debugger_launch (dbgeng trace), then retry.";

    private static final String NEEDS_TRACE =
            "This operation needs a dbgeng trace (registers/breakpoints/stepping/translation). The "
                    + "connector-less live_attach session provides the MEMORY plane only "
                    + "(read/write/scan/freeze/read_pointer_path). Use debugger_launch for control-plane ops.";

    private static final long FREEZE_INTERVAL_MS = 250;
    private static final long DEFAULT_SCAN_BUDGET = 1024L * 1024 * 1024;
    private static final long MAX_SCAN_BUDGET_MB = 8192;
    private static final int SCAN_MAX_HITS = 200_000;
    private static final int SCAN_CHUNK = 1 << 20;
    private static final int MAX_SCAN_SESSIONS = 8;
    private static final long SCAN_TTL_MS = 10 * 60 * 1000;
    private static final long LAUNCH_TIMEOUT_MS = 90_000;
    private static final int TERMINAL_TAIL_CHARS = 1500;

    private final PluginContext ctx;
    private final FlatDebuggerAPI dbg;
    private final ProcessMemory rpm = new ProcessMemory();
    private final Map<Address, byte[]> frozen = new ConcurrentHashMap<>();
    private final Map<String, ScanSession> scans = new ConcurrentHashMap<>();
    private final AtomicInteger scanSeq = new AtomicInteger();
    private final ExecutorService scanExec = Executors.newSingleThreadExecutor(r -> {
        var th = new Thread(r, "ghidra-mcp-scan");
        th.setDaemon(true);
        return th;
    });
    private volatile ScheduledExecutorService freezeTimer;
    private volatile String lastLaunch = "";
    private volatile long launchStartMs;
    private volatile TraceRmiLaunchOffer.LaunchResult lastResult;
    private volatile LiveAnchor anchor;

    private record LiveAnchor(String name, int pid, boolean wow64) {}

    public DebuggerHandlers(PluginContext ctx) {
        this.ctx = ctx;
        var tool = ctx.tool();
        this.dbg = () -> {
            var pm = tool.getService(ProgramManager.class);
            var prog = pm == null ? null : pm.getCurrentProgram();
            return new GhidraState(tool, tool.getProject(), prog, null, null, null);
        };
        Live.bind(new Live.Source() {
            @Override
            public ProcessMemory rpm() {
                return rpm;
            }

            @Override
            public Integer pid() {
                return liveAnchorPid();
            }

            @Override
            public int pointerSize() {
                var a = anchor;
                return a != null && a.wow64() ? 4 : 8;
            }
        });
    }

    public void register(RouteTable routes) {
        routes.getQuery("/debugger_status", q -> status());
        routes.getQuery("/debugger_list_targets", q -> status());
        routes.getQuery("/debugger_threads", q -> threads(q));
        routes.getQuery("/debugger_list_modules", q -> modules(q));
        routes.getQuery("/debugger_stack_trace", q -> stackTrace(q));
        routes.getQuery("/debugger_registers", q -> registers(q));
        routes.getQuery("/debugger_read_memory",
                q -> readMemory(q.get("address"), parseLen(q.get("length"))));
        routes.getQuery("/read_pointer_path", q -> readPointerPath(q.get("base"), q.get("offsets"),
                Math.min(Math.max(Http.parseIntOrDefault(q.get("value_len"), 0), 0), 65536)));
        routes.postForm("/live_read_struct", this::liveReadStruct);
        routes.getQuery("/debugger_list_breakpoints", q -> breakpoints(q));
        routes.getQuery("/debugger_translate_static_to_dynamic",
                q -> staticToDynamic(q.get("address")));
        routes.getQuery("/debugger_translate_dynamic_to_static",
                q -> dynamicToStatic(q.get("address")));

        routes.postForm("/debugger_continue", p -> control("resume"));
        routes.postForm("/debugger_step_into", p -> control("step_into"));
        routes.postForm("/debugger_step_over", p -> control("step_over"));
        routes.postForm("/debugger_break", p -> control("interrupt"));
        routes.postForm("/debugger_set_breakpoint",
                p -> setBreakpoint(p.get("address"), p.get("name")));
        routes.postForm("/debugger_remove_breakpoint",
                p -> removeBreakpoint(p.get("address")));
        routes.postForm("/live_write_memory",
                p -> writeMemory(p.get("address"), p.get("hex")));
        routes.postForm("/live_write_register",
                p -> writeRegister(p.get("register"), p.get("value")));

        routes.getQuery("/debugger_list_offers", this::listOffers);
        routes.getQuery("/debugger_backend_log", q -> backendLog());
        routes.postForm("/debugger_launch", p -> launch(p.get("offer"), p.get("args")));
        routes.postForm("/debugger_detach", p -> detach());

        routes.getQuery("/live_processes", q -> liveProcesses(q, q.get("name")));
        routes.postForm("/live_attach", p -> liveAttach(p.get("name"), p.get("pid")));
        routes.postForm("/live_release", p -> liveRelease());
        routes.getQuery("/live_modules", q -> liveModules(q));
        routes.getQuery("/live_threads", q -> liveThreads(q));
        routes.getQuery("/lua_find_state", q -> luaFindState());
        routes.postForm("/lua_exec",
                p -> luaExec(p.get("code"), p.get("state"), p.get("fn"), p.get("freeze"),
                        p.get("hook"), p.get("gettop"), p.get("loadbuffer"), p.get("pcall"),
                        p.get("settop")));
        routes.postForm("/freeze", p -> switch (p.getOrDefault("op", "on")) {
            case "off" -> unfreeze(p.get("address"));
            case "list" -> listFrozen(p);
            default -> freeze(p.get("address"), p.get("hex"));
        });
        routes.postForm("/scan", p -> switch (p.getOrDefault("op", "first")) {
            case "next" -> nextScan(p);
            case "results" -> scanResults(p);
            case "close" -> scanClose(p.get("scan_id"));
            default -> valueScan(p);
        });
    }

    public void close() {
        scanExec.shutdownNow();
        var ft = freezeTimer;
        if (ft != null) ft.shutdownNow();
        synchronized (luaLock) {
            disposeExecutor();
        }
        rpm.close();
    }

    private Trace requireTrace() {
        if (ctx.service(DebuggerTraceManagerService.class) == null) {
            throw new IllegalArgumentException(NO_DEBUGGER);
        }
        var t = dbg.getCurrentTrace();
        if (t == null) throw new IllegalArgumentException(anchor != null ? NEEDS_TRACE : NO_SESSION);
        return t;
    }

    private record LiveCtx(Trace trace, Integer pid,
            ghidra.program.model.address.AddressSpace space, boolean bigEndian) {}

    private LiveCtx liveCtx() {
        var trace = dbg.getCurrentTrace();
        if (trace != null) {
            return new LiveCtx(trace, livePid(trace),
                    trace.getBaseLanguage().getDefaultSpace(),
                    trace.getBaseLanguage().isBigEndian());
        }
        var pid = liveAnchorPid();
        if (pid != null) {
            var prog = ctx.currentProgram();
            if (prog == null) {
                throw new IllegalStateException("connector-less live op needs a program loaded "
                        + "(for its address space). Open the target binary in Ghidra.");
            }
            return new LiveCtx(null, pid, prog.getAddressFactory().getDefaultAddressSpace(),
                    prog.getLanguage().isBigEndian());
        }
        if (ctx.service(DebuggerTraceManagerService.class) == null) {
            throw new IllegalArgumentException(NO_DEBUGGER);
        }
        throw new IllegalArgumentException(NO_SESSION_OR_ATTACH);
    }

    private Address liveAddr(String address) {
        var trace = dbg.getCurrentTrace();
        if (trace != null) return dynAddr(address);
        var prog = ctx.currentProgram();
        if (prog == null) {
            throw new IllegalStateException("connector-less live op needs a program loaded");
        }
        liveCtx();
        return prog.getAddressFactory().getDefaultAddressSpace().getAddress(parseOffset(address));
    }

    private static int parseLen(String s) {
        int len = s == null ? 64 : Integer.parseInt(s);
        if (len <= 0 || len > 65536) throw new IllegalArgumentException("length must be 1..65536");
        return len;
    }

    private static String fmtOff(long o) {
        return o < 0 ? "-0x" + Long.toHexString(-o) : "+0x" + Long.toHexString(o);
    }

    private static long parseOffset(String s) {
        if (s == null || s.isBlank()) throw new IllegalArgumentException("address is required");
        var v = s.trim();
        boolean hex = v.startsWith("0x") || v.startsWith("0X");
        return Long.parseUnsignedLong(hex ? v.substring(2) : v, 16);
    }

    private long resolveLiveAddress(String s) {
        if (LiveBases.isPseudo(s)) {
            return LiveBases.resolve(rpm, requireAnchorPid(), s);
        }
        return parseOffset(s);
    }

    private Address staticAddr(String s) {
        if (s == null || s.isBlank()) throw new IllegalArgumentException("address is required");
        var prog = ctx.currentProgram();
        if (prog == null) throw new IllegalArgumentException("No program loaded");
        var a = prog.getAddressFactory().getAddress(s);
        if (a == null) throw new IllegalArgumentException("invalid address: " + s);
        return a;
    }

    private Address dynAddr(String s) {
        var trace = requireTrace();
        var prog = ctx.currentProgram();
        if (prog != null) {
            Address sa = null;
            try {
                sa = prog.getAddressFactory().getAddress(s);
            } catch (RuntimeException ignored) {
            }
            if (sa != null && prog.getMemory().contains(sa)) {
                var da = dbg.translateStaticToDynamic(sa);
                if (da != null) return da;
                long slide = programSlide(trace, prog);
                return trace.getBaseLanguage().getDefaultSpace()
                        .getAddress(sa.getOffset() + slide);
            }
        }
        return trace.getBaseLanguage().getDefaultSpace().getAddress(parseOffset(s));
    }

    private long programSlide(Trace trace, ghidra.program.model.listing.Program prog) {
        var module = programModule(trace, prog);
        if (module == null) return 0;
        var base = module.getBase(liveSnap(trace));
        return base == null ? 0 : base.getOffset() - prog.getImageBase().getOffset();
    }

    private TraceModule programModule(Trace trace, ghidra.program.model.listing.Program prog) {
        long snap = liveSnap(trace);
        var want = prog.getName().toLowerCase();
        for (TraceModule m : trace.getModuleManager().getAllModules()) {
            var n = m.getName(snap);
            if (n == null) continue;
            var slashed = n.replace('\\', '/');
            int slash = slashed.lastIndexOf('/');
            var leaf = slash >= 0 ? slashed.substring(slash + 1) : slashed;
            if (leaf.equalsIgnoreCase(want)) return m;
        }
        return null;
    }

    private long liveSnap(Trace trace) {
        var ts = ctx.service(DebuggerTargetService.class);
        var target = ts == null ? null : ts.getTarget(trace);
        return target != null ? target.getSnap() : dbg.getCurrentSnap();
    }

    private static final java.util.regex.Pattern PID_PATH =
            java.util.regex.Pattern.compile("Processes\\[(\\d+)]");
    private static final Pattern STRUCT_FIELD =
            Pattern.compile("\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*[:=]\\s*([A-Za-z0-9_]+)"
                    + "(?:\\[(\\d+)])?\\s*(?:\\+|@)\\s*(0x[0-9a-fA-F]+|\\d+)\\s*");

    private Integer livePid(Trace trace) {
        var thread = dbg.getCurrentThread();
        var pid = pidFromPath(thread == null ? null : thread.getPath());
        if (pid != null) return pid;
        for (TraceThread th : trace.getThreadManager().getAllThreads()) {
            pid = pidFromPath(th.getPath());
            if (pid != null) return pid;
        }
        try {
            return Integer.valueOf(trace.getName().trim());
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Integer pidFromPath(String path) {
        if (path == null) return null;
        var m = PID_PATH.matcher(path);
        return m.find() ? Integer.valueOf(m.group(1)) : null;
    }

    private byte[] rpmRead(Integer pid, Address da, int length) {
        if (pid == null || !rpm.available()) return null;
        var b = rpm.read(pid, da.getOffset(), length);
        return (b == null || b.length == 0) ? null : b;
    }

    private void syncPresent(Trace trace) {
        var tm = ctx.service(DebuggerTraceManagerService.class);
        var ts = ctx.service(DebuggerTargetService.class);
        if (tm == null || ts == null) return;
        var target = ts.getTarget(trace);
        if (target == null) return;
        try {
            tm.activate(tm.resolveTarget(target),
                    DebuggerTraceManagerService.ActivationCause.FOLLOW_PRESENT);
        } catch (RuntimeException ignored) {
        }
    }

    private void invalidateCaches(Trace trace) {
        var ts = ctx.service(DebuggerTargetService.class);
        var target = ts == null ? null : ts.getTarget(trace);
        if (target != null) {
            try {
                target.invalidateMemoryCaches();
            } catch (RuntimeException ignored) {
            }
        }
    }

    private String detach() {
        var trace = requireTrace();
        var ts = ctx.service(DebuggerTargetService.class);
        var target = ts == null ? null : ts.getTarget(trace);
        if (target == null) throw new IllegalStateException("No target for current trace");
        var name = trace.getName();
        lastLaunch = "";
        var fut = java.util.concurrent.CompletableFuture.runAsync(target::disconnect);
        try {
            fut.get(5, TimeUnit.SECONDS);
            return "detached from " + name + " (released without killing; if it was noninvasively suspended it resumes)";
        } catch (java.util.concurrent.TimeoutException e) {
            return "detach requested for " + name + "; the back-end disconnect is taking >5s (a noninvasive "
                    + "dbgeng connector can block at its REPL). The target is being released — if a trace lingers, "
                    + "close it in the Ghidra GUI. Connector-less live_attach needs no detach.";
        } catch (Exception e) {
            return "detach of " + name + " returned: " + e.getMessage();
        }
    }

    private void requireRpm() {
        if (!rpm.available()) {
            throw new IllegalStateException(
                    "Direct process access unavailable (non-Windows host or JNA not loaded).");
        }
    }

    private String liveProcesses(Map<String, String> q, String name) {
        requireRpm();
        if (name != null && !name.isBlank()) {
            var cands = ProcessResolver.resolve(rpm, name);
            var t = Responses.table(q,
                    new String[]{"pid", "name", "openable", "wow64", "modules", "status"}, cands.size());
            for (var c : cands) {
                t.row(c.pid(), c.name(), c.openable(), c.wow64(), c.moduleCount(),
                        c.openable() ? "ready" : winErr(c.openError()));
            }
            return t.build();
        }
        var procs = rpm.listProcesses();
        var t = Responses.table(q, new String[]{"pid", "name"}, procs.size());
        for (var p : procs) t.row(p.pid(), p.name());
        return t.build();
    }

    private String liveAttach(String name, String pidStr) {
        requireRpm();
        int pid;
        String resolvedName;
        var extra = new StringBuilder();
        if (pidStr != null && !pidStr.isBlank()) {
            pid = Integer.parseInt(pidStr.trim());
            int err = rpm.probeOpen(pid);
            if (err != 0) throw new IllegalStateException(openFailure(name, pid, err));
            resolvedName = (name == null || name.isBlank()) ? "pid" + pid : name;
        } else {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("name or pid is required (see live_processes)");
            }
            var cands = ProcessResolver.resolve(rpm, name);
            if (cands.isEmpty()) {
                throw new IllegalStateException("No running process named '" + name
                        + "'. Confirm it is running (live_processes).");
            }
            var best = cands.get(0);
            if (!best.openable()) throw new IllegalStateException(openFailure(name, best.pid(), best.openError()));
            pid = best.pid();
            resolvedName = best.name();
            long openable = cands.stream().filter(ProcessResolver.Candidate::openable).count();
            if (openable > 1) {
                extra.append("\nNOTE: ").append(openable).append(" processes named '").append(name)
                        .append("' are open; picked pid ").append(pid)
                        .append(" (most modules). Pass pid= to choose another (see live_processes).");
            }
        }
        boolean wow64 = rpm.isWow64(pid);
        synchronized (luaLock) {
            disposeExecutor();
        }
        anchor = new LiveAnchor(resolvedName, pid, wow64);
        var mods = rpm.modules(pid);
        int threads = rpm.threadIds(pid).size();
        long mainBase = mainModuleBase(mods, resolvedName);
        var sb = new StringBuilder();
        sb.append("attached ").append(resolvedName).append(" pid=").append(pid)
                .append(" (").append(wow64 ? "WOW64/32-bit" : "64-bit").append(", connector-less)\n");
        sb.append("main_base=0x").append(Long.toHexString(mainBase))
                .append(", modules=").append(mods.size())
                .append(", threads=").append(threads).append('\n');
        sb.append("memory plane ready: read_memory / read_pointer_path resolve directly via this "
                + "process (no dbgeng/trace). For registers/breakpoints/stepping use debugger_launch.");
        return sb.append(extra).toString();
    }

    private static final long DEFAULT_LUA_EXEC_FN = 0x9e64d0L;
    private static final long DEFAULT_LUA_HOOK = 0x766620L;
    private static final long DEFAULT_LUA_GETTOP = 0x9c7c90L;
    private static final long DEFAULT_LUA_LOADBUFFER = 0x9c9c70L;
    private static final long DEFAULT_LUA_PCALL = 0x9c8aa0L;
    private static final long DEFAULT_LUA_SETTOP = 0x9c7cb0L;
    private static final int STILL_ACTIVE = 259;
    private static final int LUA_EXEC_TIMEOUT_MS = 3000;
    private volatile Lua.ExecutorHandle luaExecutor;
    private final Object luaLock = new Object();

    private void disposeExecutor() {
        var h = luaExecutor;
        if (h == null) return;
        try {
            Lua.uninstall(rpm, h);
        } catch (RuntimeException ignored) {
        }
        luaExecutor = null;
    }

    private int requireLivePid() {
        var pid = liveAnchorPid();
        if (pid == null) throw new IllegalStateException(NO_SESSION_OR_ATTACH);
        return pid;
    }

    private String luaFindState() {
        int pid = requireLivePid();
        int ptr = anchorPtrSize();
        var info = Lua.detect(rpm, pid, ptr);
        long state = Lua.findState(rpm, pid, ptr);
        var sb = new StringBuilder("lua detect: version=")
                .append(info.version() == null ? "(none found)" : info.version())
                .append(info.luaJit() ? " [LuaJIT]" : "").append(", ptr_size=").append(ptr);
        if (info.hasDll()) {
            sb.append("\ndll@0x").append(Long.toHexString(info.moduleBase()))
                    .append(" loadbuffer=0x").append(Long.toHexString(info.loadBuffer()))
                    .append(" pcall=0x").append(Long.toHexString(info.pcall()))
                    .append(" dostring=0x").append(Long.toHexString(info.doString()));
        }
        sb.append('\n').append(state == 0
                ? "lua_State: NOT found by image scan. Pass state= to lua_exec (hook lua_pcall and read its "
                        + "first arg, or walk the engine singleton)."
                : "lua_State = 0x" + Long.toHexString(state)
                        + " (validated via the global_State mainthread back-reference)");
        return sb.toString();
    }

    private long offsetOr(String s, long fallback) {
        return (s == null || s.isBlank()) ? fallback : parseOffset(s);
    }

    private String luaExec(String code, String stateStr, String fnStr, String freezeStr,
            String hookStr, String gettopStr, String loadbufferStr, String pcallStr, String settopStr) {
        if (code == null || code.isBlank()) throw new IllegalArgumentException("code is required");
        int pid = requireLivePid();
        int ptr = anchorPtrSize();
        var info = Lua.detect(rpm, pid, ptr);
        long fn;
        if (fnStr != null && !fnStr.isBlank()) {
            fn = parseOffset(fnStr);
        } else if (info.doString() != 0) {
            fn = info.doString();
        } else {
            fn = DEFAULT_LUA_EXEC_FN;
        }
        long state;
        if (stateStr != null && !stateStr.isBlank()) {
            state = parseOffset(stateStr);
        } else {
            state = Lua.findState(rpm, pid, ptr);
            if (state == 0) {
                throw new IllegalStateException("could not auto-detect lua_State; run lua_find_state or "
                        + "pass state= (and fn= for non-Alicia targets)");
            }
        }
        boolean unsafe = "1".equals(freezeStr) || "true".equalsIgnoreCase(freezeStr);
        if (unsafe) {
            int rc = Lua.exec(rpm, pid, state, fn, code, ptr, true);
            var legacy = rc == 1 ? " (executor ok)"
                    : rc == 0 ? " (executor reported a Lua error — check syntax/runtime)"
                    : rc == -2 ? " (CreateRemoteThread failed)"
                    : rc == STILL_ACTIVE ? " (TIMED OUT/STILL_ACTIVE — remote thread hung on the heap"
                            + " lock; this unsafe path crashes a running VM, prefer the default)" : "";
            return "lua_exec (UNSAFE remote-thread) ran: L=0x" + Long.toHexString(state) + " fn=0x"
                    + Long.toHexString(fn) + " thread_exit=" + rc + legacy;
        }
        long hook = offsetOr(hookStr, DEFAULT_LUA_HOOK);
        long gettop = offsetOr(gettopStr, DEFAULT_LUA_GETTOP);
        long loadbuffer = offsetOr(loadbufferStr, DEFAULT_LUA_LOADBUFFER);
        long pcall = offsetOr(pcallStr, DEFAULT_LUA_PCALL);
        long settop = offsetOr(settopStr, DEFAULT_LUA_SETTOP);
        Lua.ExecResult res;
        synchronized (luaLock) {
            var h = luaExecutor;
            if (h != null && (h.pid() != pid || !h.sameAddresses(hook, gettop, loadbuffer, pcall, settop))) {
                disposeExecutor();
                h = null;
            }
            if (h == null) {
                byte[] original = new byte[5];
                try {
                    var prog = ctx.currentProgram();
                    var addr = prog.getAddressFactory().getDefaultAddressSpace().getAddress(hook);
                    int got = prog.getMemory().getBytes(addr, original);
                    if (got < original.length) {
                        throw new IllegalStateException("only " + got + " of 5 bytes readable at hook 0x"
                                + Long.toHexString(hook) + " (end of memory block?)");
                    }
                } catch (IllegalStateException e) {
                    throw e;
                } catch (Exception e) {
                    throw new IllegalStateException("cannot read hook prologue from program: " + e.getMessage());
                }
                h = Lua.install(rpm, pid, state, hook, ptr, original, gettop, loadbuffer, pcall, settop);
                luaExecutor = h;
            }
            res = Lua.execMailbox(rpm, h, state, code, LUA_EXEC_TIMEOUT_MS);
            if (res.rc() == Lua.EXEC_TIMEOUT) {
                disposeExecutor();
                return "lua_exec TIMED OUT — per-frame hook at 0x" + Long.toHexString(hook)
                        + " did not fire within " + LUA_EXEC_TIMEOUT_MS
                        + "ms (game paused/minimized, or hook not installed); executor uninstalled";
            }
        }
        boolean ok = res.rc() == 0;
        String ret = res.data() != null
                ? new String(res.data(), java.nio.charset.StandardCharsets.UTF_8) : null;
        var sb = new StringBuilder("lua_exec (safe/in-thread): L=0x").append(Long.toHexString(state))
                .append(" frame_hook=0x").append(Long.toHexString(hook))
                .append(ok ? " OK" : " LUA-ERROR");
        if (ret != null) {
            sb.append(ok ? "\nreturn: " : "\nerror: ").append(ret);
        } else if (res.tt() != 0) {
            sb.append("\nreturn: non-string value (lua type tt=").append(res.tt()).append(")");
        } else {
            sb.append("\nreturn: nil");
        }
        return sb.toString();
    }

    private String liveRelease() {
        var a = anchor;
        if (a == null) throw new IllegalStateException("No live session anchored");
        synchronized (luaLock) {
            disposeExecutor();
        }
        anchor = null;
        return "released anchor " + a.name() + " pid=" + a.pid()
                + " (process untouched; OpenProcess handle closed lazily)";
    }

    private String liveModules(Map<String, String> q) {
        int pid = requireAnchorPid();
        var mods = rpm.modules(pid);
        mods.sort(Comparator.comparingLong(ProcessMemory.Module::base));
        var t = Responses.table(q, new String[]{"name", "base", "size"}, mods.size());
        for (var m : mods) {
            t.row(m.name(), "0x" + Long.toHexString(m.base()), m.size());
        }
        return t.build();
    }

    private String liveThreads(Map<String, String> q) {
        int pid = requireAnchorPid();
        var ids = rpm.threadIds(pid);
        var t = Responses.table(q, new String[]{"tid"}, ids.size());
        for (var id : ids) t.row(id);
        return t.build();
    }

    private static long mainModuleBase(List<ProcessMemory.Module> mods, String name) {
        var leaf = name.toLowerCase();
        for (var m : mods) {
            if (m.name().equalsIgnoreCase(leaf)) return m.base();
        }
        return mods.isEmpty() ? 0 : mods.get(0).base();
    }

    private int requireAnchorPid() {
        var pid = liveAnchorPid();
        if (pid == null) {
            throw new IllegalStateException("No live session. Call live_attach (name= or pid=) first.");
        }
        return pid;
    }

    private Integer liveAnchorPid() {
        var a = anchor;
        if (a == null) return null;
        if (rpm.probeOpen(a.pid()) == 0) return a.pid();
        for (var c : ProcessResolver.resolve(rpm, a.name())) {
            if (c.openable()) {
                anchor = new LiveAnchor(a.name(), c.pid(), c.wow64());
                return c.pid();
            }
        }
        return null;
    }

    private Integer activePid() {
        var trace = dbg.getCurrentTrace();
        if (trace != null) {
            var pid = livePid(trace);
            if (pid != null) return pid;
        }
        return liveAnchorPid();
    }

    private int anchorPtrSize() {
        var prog = ctx.currentProgram();
        if (prog != null) return prog.getDefaultPointerSize();
        var a = anchor;
        return a != null && a.wow64() ? 4 : 8;
    }

    private boolean anchorBigEndian() {
        var prog = ctx.currentProgram();
        return prog != null && prog.getLanguage().isBigEndian();
    }

    private String anchorReadMemory(String address, int length) {
        int pid = requireAnchorPid();
        long off = resolveLiveAddress(address);
        var b = rpm.read(pid, off, length);
        if (b == null) {
            throw new IllegalStateException("Failed to read " + length + " bytes at 0x"
                    + Long.toHexString(off) + " (pid " + pid + "; unmapped or process exited)");
        }
        return "0x" + Long.toHexString(off) + "\t" + b.length + "\t" + Bufs.hex(b);
    }

    private String anchorWriteMemory(String address, String hex) {
        int pid = requireAnchorPid();
        long off = resolveLiveAddress(address);
        var bytes = Bufs.parseHex(hex);
        if (!rpm.write(pid, off, bytes)) {
            throw new IllegalStateException("WriteProcessMemory failed at 0x" + Long.toHexString(off)
                    + " (pid " + pid + "; write-protected page or process exited)");
        }
        var back = rpm.read(pid, off, bytes.length);
        var verify = Arrays.equals(back, bytes) ? " (verified)"
                : " WARNING: read-back mismatch (got " + (back == null ? "null" : Bufs.hex(back))
                        + "); page may be write-protected or the game rewrites it each frame (try freeze_value)";
        return "Wrote " + bytes.length + " byte(s) to 0x" + Long.toHexString(off) + verify;
    }

    private String anchorPointerPath(String base, String offsetsStr, int valueLen) {
        if (base == null || base.isBlank()) throw new IllegalArgumentException("base is required");
        int pid = requireAnchorPid();
        int ptrSize = anchorPtrSize();
        boolean bigEndian = anchorBigEndian();
        long[] offsets = PointerPath.parseOffsets(offsetsStr);
        if (offsets.length == 0) offsets = new long[]{0};
        long cur = resolveLiveAddress(base);
        var sb = new StringBuilder();
        sb.append("# base=0x").append(Long.toHexString(cur)).append(", ptr_size=").append(ptrSize)
                .append(" (connector-less)\nstep\tat\tnext\n");
        for (long offset : offsets) {
            byte[] pb = rpm.read(pid, cur, ptrSize);
            if (pb == null || pb.length < ptrSize) {
                throw new IllegalStateException("Failed to read pointer at 0x" + Long.toHexString(cur));
            }
            long ptr = PointerPath.toUnsignedLong(pb, ptrSize, bigEndian);
            long next = ptr + offset;
            sb.append(fmtOff(offset)).append("\t0x")
                    .append(Long.toHexString(cur)).append("\t0x").append(Long.toHexString(next)).append('\n');
            cur = next;
        }
        sb.append("final\t0x").append(Long.toHexString(cur));
        int valLen = valueLen > 0 ? valueLen : ptrSize;
        byte[] vb = rpm.read(pid, cur, valLen);
        if (vb != null) {
            sb.append('\t').append(Bufs.hex(vb)).append("\t(value_len=").append(valLen).append(')');
        } else {
            sb.append("\t(final address unmapped/unreadable)");
        }
        return sb.append('\n').toString();
    }

    private static String openFailure(String name, int pid, int err) {
        var who = (name == null || name.isBlank()) ? "pid " + pid : "'" + name + "' (pid " + pid + ")";
        var msg = "Cannot open " + who + ": " + winErr(err) + ".";
        if (err == ProcessMemory.ERROR_ACCESS_DENIED) {
            msg += " The target runs at a higher integrity level. Relaunch Ghidra as Administrator "
                    + "(SeDebugPrivilege) — this blocks BOTH connector-less and dbgeng attach.";
        }
        return msg;
    }

    private static String winErr(int err) {
        return switch (err) {
            case 0 -> "ok";
            case 5 -> "ERROR_ACCESS_DENIED (5)";
            case 87 -> "ERROR_INVALID_PARAMETER (87, bad/stale pid?)";
            default -> "win32 error " + err;
        };
    }

    private void enterTargetControl(Trace trace) {
        var control = ctx.service(DebuggerControlService.class);
        if (control != null) control.setCurrentMode(trace, ControlMode.RW_TARGET);
    }

    private boolean targetAlive() {
        var tm = ctx.service(DebuggerTraceManagerService.class);
        if (tm == null) return false;
        var coords = tm.getCurrent();
        return coords != null && coords.isAlive();
    }

    private String status() {
        if (ctx.service(DebuggerTraceManagerService.class) == null) return NO_DEBUGGER;
        if (!lastLaunch.isBlank() && dbg.getCurrentTrace() == null) {
            if (!lastLaunch.startsWith("launching")) return lastLaunch;
            long secs = (System.currentTimeMillis() - launchStartMs) / 1000;
            return lastLaunch + " (" + secs + "s elapsed; auto-diagnoses at " + (LAUNCH_TIMEOUT_MS / 1000)
                    + "s — if it stalls, debugger_backend_log shows the connector's own error)";
        }
        var t = dbg.getCurrentTrace();
        if (t == null) return NO_SESSION;
        var sb = new StringBuilder(256);
        sb.append("trace=").append(t.getName()).append('\n');
        sb.append("alive=").append(targetAlive()).append('\n');
        sb.append("snap=").append(dbg.getCurrentSnap()).append('\n');
        var thread = dbg.getCurrentThread();
        sb.append("thread=").append(thread == null ? "(none)" : thread.getPath()).append('\n');
        try {
            var pc = dbg.getProgramCounter();
            sb.append("pc=").append(pc == null ? "(unknown)" : Responses.addr(pc)).append('\n');
        } catch (RuntimeException e) {
            sb.append("pc=(unavailable)\n");
        }
        if (!lastLaunch.isBlank()) sb.append("last_launch=").append(lastLaunch).append('\n');
        return sb.toString();
    }

    private String threads(java.util.Map<String, String> q) {
        var trace = requireTrace();
        long snap = dbg.getCurrentSnap();
        var current = dbg.getCurrentThread();
        var t = Responses.table(q, new String[]{"key", "name", "path", "alive", "current"}, 8);
        for (TraceThread th : trace.getThreadManager().getAllThreads()) {
            t.row(th.getKey(), th.getName(snap), th.getPath(),
                    th.isAlive(Lifespan.at(snap)), th == current);
        }
        return t.build();
    }

    private String modules(java.util.Map<String, String> q) {
        if (anchor != null && dbg.getCurrentTrace() == null) return liveModules(q);
        var trace = requireTrace();
        long snap = dbg.getCurrentSnap();
        var t = Responses.table(q, new String[]{"name", "base", "length"}, 16);
        for (TraceModule m : trace.getModuleManager().getAllModules()) {
            t.row(m.getName(snap), Responses.addr(m.getBase(snap)), m.getLength(snap));
        }
        return t.build();
    }

    private String stackTrace(java.util.Map<String, String> q) {
        var trace = requireTrace();
        var thread = resolveThread(trace, q);
        if (thread == null) throw new IllegalArgumentException("No current thread (attach and stop a target first)");
        long snap = dbg.getCurrentSnap();
        TraceStack stack = trace.getStackManager().getLatestStack(thread, snap);
        if (stack == null) throw new IllegalStateException("No stack for current thread at snap " + snap);
        var prog = ctx.currentProgram();
        var t = Responses.table(q, new String[]{"level", "pc", "static", "function"}, 16);
        for (TraceStackFrame f : stack.getFrames(snap)) {
            Address pc = f.getProgramCounter(snap);
            Address sa = pc == null ? null : safeToStatic(pc);
            String fn = "";
            if (sa != null && prog != null) {
                Function func = prog.getFunctionManager().getFunctionContaining(sa);
                if (func != null) fn = func.getName();
            }
            t.row(f.getLevel(), pc == null ? "" : Responses.addr(pc),
                    sa == null ? "" : Responses.addr(sa), fn);
        }
        return t.build();
    }

    private TraceThread resolveThread(Trace trace, java.util.Map<String, String> q) {
        var want = q.get("thread");
        if (want == null || want.isBlank()) return dbg.getCurrentThread();
        long snap = dbg.getCurrentSnap();
        for (TraceThread th : trace.getThreadManager().getAllThreads()) {
            if (want.equals(Long.toString(th.getKey()))) return th;
        }
        for (TraceThread th : trace.getThreadManager().getAllThreads()) {
            var name = th.getName(snap);
            if (want.equalsIgnoreCase(name) || want.equals(th.getPath())
                    || (name != null && name.startsWith(want + " "))) return th;
        }
        throw new IllegalArgumentException(
                "No thread matching '" + want + "' (use the key column from debugger_threads)");
    }

    private Address safeToStatic(Address dyn) {
        try {
            return dbg.translateDynamicToStatic(dyn);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private String registers(java.util.Map<String, String> q) {
        var trace = requireTrace();
        var thread = resolveThread(trace, q);
        if (thread == null) throw new IllegalArgumentException("No current thread (attach and stop a target first)");
        var platform = dbg.getCurrentPlatform();
        long snap = dbg.getCurrentSnap();
        int frame = dbg.getCurrentFrame();
        boolean full = "1".equals(q.get("full"));
        var regs = new java.util.ArrayList<Register>();
        for (Register r : trace.getBaseLanguage().getRegisters()) {
            if (r.isBaseRegister() && !r.isProcessorContext()
                    && (full || io.github.imjustprism.ghidra.mcp.util.Registers.isCommon(r.getName()))) {
                regs.add(r);
            }
        }
        java.util.Collection<RegisterValue> values;
        try {
            values = dbg.readRegisters(platform, thread, frame, snap, regs);
        } catch (RuntimeException e) {
            if (String.valueOf(e).contains("Running")) {
                throw new IllegalArgumentException("Target is running — call debugger_break first");
            }
            throw e;
        }
        var t = Responses.table(q, new String[]{"register", "value"}, regs.size());
        for (RegisterValue rv : values) {
            if (rv == null) continue;
            BigInteger v = rv.getUnsignedValue();
            t.row(rv.getRegister().getName(), v == null ? "" : v.toString(16));
        }
        return t.build();
    }

    private String readMemory(String address, int length) {
        if (dbg.getCurrentTrace() == null && anchor != null) return anchorReadMemory(address, length);
        var trace = requireTrace();
        var da = dynAddr(address);
        byte[] b = readLiveBytes(trace, livePid(trace), da, length);
        if (b == null) {
            throw new IllegalStateException("Error reading live memory at " + Responses.addr(da));
        }
        return Responses.addr(da) + "\t" + b.length + "\t" + Bufs.hex(b);
    }

    private byte[] readLiveBytes(Trace trace, Integer pid, Address da, int length) {
        byte[] b = rpmRead(pid, da, length);
        if (b != null) return b;
        try {
            syncPresent(trace);
            invalidateCaches(trace);
            return dbg.readMemory(trace, liveSnap(trace), da, length, TaskMonitor.DUMMY);
        } catch (Exception e) {
            return null;
        }
    }

    private String readPointerPath(String base, String offsetsStr, int valueLen) {
        if (base == null || base.isBlank()) throw new IllegalArgumentException("base is required");
        if (dbg.getCurrentTrace() == null && anchor != null) return anchorPointerPath(base, offsetsStr, valueLen);
        var trace = requireTrace();
        var pid = livePid(trace);
        boolean bigEndian = trace.getBaseLanguage().isBigEndian();
        long[] offsets = PointerPath.parseOffsets(offsetsStr);
        if (offsets.length == 0) offsets = new long[]{0};
        var cur = dynAddr(base);

        var program = ctx.currentProgram();
        int ptrSize = program != null ? program.getDefaultPointerSize() : cur.getAddressSpace().getPointerSize();
        var sb = new StringBuilder();
        sb.append("# base=").append(Responses.addr(cur)).append(", ptr_size=").append(ptrSize).append('\n');
        sb.append("step\tat\tnext\n");
        for (int i = 0; i < offsets.length; i++) {
            byte[] pb = readLiveBytes(trace, pid, cur, ptrSize);
            if (pb == null) throw new IllegalStateException("Failed to read pointer at " + Responses.addr(cur));
            long ptr = PointerPath.toUnsignedLong(pb, ptrSize, bigEndian);
            Address next;
            try {
                next = cur.getNewAddress(ptr).addNoWrap(offsets[i]);
            } catch (ghidra.program.model.address.AddressOverflowException | RuntimeException e) {
                throw new IllegalStateException("Pointer out of range at step " + i + ": ["
                        + Responses.addr(cur) + "]=0x" + Long.toHexString(ptr)
                        + " + 0x" + Long.toHexString(offsets[i]));
            }
            sb.append(fmtOff(offsets[i])).append('\t')
                    .append(Responses.addr(cur)).append('\t').append(Responses.addr(next)).append('\n');
            cur = next;
        }
        sb.append("final\t").append(Responses.addr(cur));
        if (valueLen > 0) {
            byte[] vb = readLiveBytes(trace, pid, cur, valueLen);
            if (vb == null) {
                throw new IllegalStateException("Resolved final=" + Responses.addr(cur)
                        + " but failed to read " + valueLen + " bytes there (unmapped/inaccessible)");
            }
            sb.append('\t').append(Bufs.hex(vb)).append("\t(value_len=").append(valueLen).append(')');
        } else {
            byte[] vb = readLiveBytes(trace, pid, cur, ptrSize);
            if (vb != null) {
                sb.append('\t').append(Bufs.hex(vb))
                        .append("\t(default ").append(ptrSize).append("B; pass value_len for more)");
            } else {
                sb.append("\t(final address unmapped/unreadable)");
            }
        }
        return sb.append('\n').toString();
    }

    private String liveReadStruct(Map<String, String> q) {
        var address = q.get("address");
        var schema = q.get("schema");
        if (address == null || address.isBlank()) throw new IllegalArgumentException("address is required");
        if (schema == null || schema.isBlank()) throw new IllegalArgumentException("schema is required");
        var lc = liveCtx();
        var program = ctx.currentProgram();
        int ptr = program != null ? program.getDefaultPointerSize() : lc.space().getPointerSize();
        var fields = parseStructSchema(schema, ptr);
        long snap = lc.trace() != null ? liveSnap(lc.trace()) : 0;
        long baseOff = LiveBases.isPseudo(address) ? resolveLiveAddress(address) : parseOffset(address);
        var base = lc.space().getAddress(baseOff);
        var t = Responses.table(q, new String[]{"field", "type", "offset", "address", "value"}, fields.size());
        for (var f : fields) {
            Address at;
            try {
                at = base.add(f.offset());
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("field out of address space: " + f.name());
            }
            var data = readScanChunk(lc, snap, at, f.size(), lc.pid());
            t.row(f.name(), f.type(), "0x" + Long.toHexString(f.offset()), Responses.addr(at),
                    data == null ? "?" : data.length < f.size()
                            ? "short:" + Bufs.hex(data) : decodeStructField(f, data, lc.bigEndian(), ptr));
        }
        return t.build();
    }

    private String breakpoints(java.util.Map<String, String> q) {
        var t = Responses.table(q, new String[]{"address", "name", "kinds", "length"}, 8);
        for (LogicalBreakpoint b : dbg.getAllBreakpoints()) {
            t.row(Responses.addr(b.getAddress()), b.getName(), b.getKinds(), b.getLength());
        }
        return t.build();
    }

    private Long connectorlessSlide(ghidra.program.model.listing.Program prog) {
        var a = anchor;
        if (prog == null || a == null) return null;
        var mods = rpm.modules(a.pid());
        if (mods.isEmpty()) return null;
        return mainModuleBase(mods, prog.getName()) - prog.getImageBase().getOffset();
    }

    private String staticToDynamic(String address) {
        var prog = ctx.currentProgram();
        if (anchor != null && dbg.getCurrentTrace() == null) {
            var slide = connectorlessSlide(prog);
            if (slide == null) return "No live main-module base for connector-less translation";
            return "0x" + Long.toHexString(staticAddr(address).getOffset() + slide);
        }
        var trace = requireTrace();
        var sa = staticAddr(address);
        var da = dbg.translateStaticToDynamic(sa);
        if (da == null && prog != null && prog.getMemory().contains(sa)) {
            long slide = programSlide(trace, prog);
            da = trace.getBaseLanguage().getDefaultSpace().getAddress(sa.getOffset() + slide);
        }
        return da == null ? "No mapping for static address " + address : Responses.addr(da);
    }

    private String dynamicToStatic(String address) {
        var prog = ctx.currentProgram();
        if (anchor != null && dbg.getCurrentTrace() == null) {
            var slide = connectorlessSlide(prog);
            if (slide == null) return "No live main-module base for connector-less translation";
            var cand = prog.getImageBase().getNewAddress(parseOffset(address) - slide);
            return prog.getMemory().contains(cand)
                    ? Responses.addr(cand) : "No mapping for dynamic address " + address;
        }
        var trace = requireTrace();
        var da = trace.getBaseLanguage().getDefaultSpace().getAddress(parseOffset(address));
        var sa = safeToStatic(da);
        if (sa == null && prog != null) {
            long slide = programSlide(trace, prog);
            var cand = prog.getImageBase().getNewAddress(da.getOffset() - slide);
            if (prog.getMemory().contains(cand)) sa = cand;
        }
        return sa == null ? "No mapping for dynamic address " + address : Responses.addr(sa);
    }

    private String control(String op) {
        var trace = requireTrace();
        boolean ok = switch (op) {
            case "resume" -> dbg.resume();
            case "step_into" -> dbg.stepInto();
            case "step_over" -> dbg.stepOver();
            case "interrupt" -> dbg.interrupt();
            default -> throw new IllegalArgumentException("unknown control op: " + op);
        };
        if (!ok) throw new IllegalStateException(op + " failed (target not alive or busy?)");
        syncPresent(trace);
        return op + " ok (snap=" + dbg.getCurrentSnap() + ")";
    }

    private String setBreakpoint(String address, String name) {
        var prog = ctx.currentProgram();
        if (prog == null) throw new IllegalArgumentException("No program loaded");
        requireTrace();
        var loc = new ProgramLocation(prog, staticAddr(address));
        var bps = dbg.breakpointSetSoftwareExecute(loc, name == null ? "" : name);
        return bps.isEmpty()
                ? "No breakpoint placed at " + address + " (target may not support it here)"
                : "Set " + bps.size() + " breakpoint(s) at " + address;
    }

    private String removeBreakpoint(String address) {
        var prog = ctx.currentProgram();
        if (prog == null) throw new IllegalArgumentException("No program loaded");
        requireTrace();
        var loc = new ProgramLocation(prog, staticAddr(address));
        boolean ok = dbg.breakpointsClear(loc);
        return ok ? "Cleared breakpoint(s) at " + address : "No breakpoint at " + address;
    }

    private String writeMemory(String address, String hex) {
        if (hex == null || hex.isBlank()) throw new IllegalArgumentException("hex is required");
        if (dbg.getCurrentTrace() == null && anchor != null) return anchorWriteMemory(address, hex);
        var trace = requireTrace();
        var da = dynAddr(address);
        var bytes = Bufs.parseHex(hex);
        var pid = livePid(trace);
        if (pid != null && rpm.write(pid, da.getOffset(), bytes)) {
            return "Wrote " + bytes.length + " byte(s) to " + Responses.addr(da) + verifyWrite(trace, da, bytes);
        }
        syncPresent(trace);
        enterTargetControl(trace);
        boolean ok = dbg.writeMemory(da, bytes);
        if (!ok) {
            throw new IllegalStateException(
                    "Write failed at " + Responses.addr(da) + " (target not alive?)");
        }
        return "Wrote " + bytes.length + " byte(s) to " + Responses.addr(da) + verifyWrite(trace, da, bytes);
    }

    private String verifyWrite(Trace trace, Address da, byte[] expected) {
        try {
            byte[] back = rpmRead(livePid(trace), da, expected.length);
            if (back == null) {
                invalidateCaches(trace);
                back = dbg.readMemory(trace, liveSnap(trace), da, expected.length, TaskMonitor.DUMMY);
            }
            if (Arrays.equals(back, expected)) return " (verified)";
            return " WARNING: read-back mismatch (got " + Bufs.hex(back) + "); target may be"
                    + " write-protected or the value is overwritten by the game each frame (try freeze_value)";
        } catch (Exception e) {
            return " (write ok; verify read failed: " + e.getMessage() + ")";
        }
    }

    private String writeRegister(String register, String value) {
        if (register == null || register.isBlank()) throw new IllegalArgumentException("register is required");
        if (value == null || value.isBlank()) throw new IllegalArgumentException("value is required");
        var trace = requireTrace();
        BigInteger v = parseBigInt(value);
        enterTargetControl(trace);
        boolean ok = dbg.writeRegister(register, v);
        if (!ok) {
            throw new IllegalStateException(
                    "Write failed for register " + register + " (target not alive or bad name?)");
        }
        return "Wrote " + register + "=0x" + v.toString(16);
    }

    private static BigInteger parseBigInt(String s) {
        var v = s.trim();
        return (v.startsWith("0x") || v.startsWith("0X"))
                ? new BigInteger(v.substring(2), 16) : new BigInteger(v);
    }

    private String listOffers(Map<String, String> q) {
        var prog = ctx.currentProgram();
        if (prog == null) throw new IllegalArgumentException("No program loaded (offers are per-program)");
        var svc = ctx.service(TraceRmiLauncherService.class);
        if (svc == null) throw new IllegalStateException("Launcher service unavailable");
        var t = Responses.table(q, new String[]{"offer", "title", "requiresImage", "params"}, 16);
        for (var offer : svc.getOffers(prog)) {
            t.row(offer.getConfigName(), offer.getTitle(), offer.requiresImage(),
                    String.join("|", offer.getParameters().keySet()));
        }
        return t.build();
    }

    private String launch(String offerName, String args) {
        if (offerName == null || offerName.isBlank()) {
            throw new IllegalArgumentException("offer is required (see debugger_list_offers)");
        }
        var prog = ctx.currentProgram();
        if (prog == null) throw new IllegalArgumentException("No program loaded");
        var svc = ctx.service(TraceRmiLauncherService.class);
        if (svc == null) throw new IllegalStateException("Launcher service unavailable");
        TraceRmiLaunchOffer offer = null;
        for (var o : svc.getOffers(prog)) {
            if (o.getConfigName().equals(offerName)) {
                offer = o;
                break;
            }
        }
        if (offer == null) throw new IllegalArgumentException("No offer '" + offerName + "'. See debugger_list_offers.");
        var theOffer = offer;
        var params = theOffer.getParameters();
        var unmatched = new ArrayList<String>();
        var resolved = new LinkedHashMap<String, String>();
        for (var e : parseKv(args).entrySet()) {
            var key = resolveParamKey(params.keySet(), e.getKey());
            if (key == null) unmatched.add(e.getKey());
            else resolved.put(key, e.getValue());
        }
        preflightPid(resolved);
        closeStaleResult();
        lastLaunch = "launching '" + offerName + "'...";
        launchStartMs = System.currentTimeMillis();
        var launcher = new Thread(() -> runLaunch(offerName, theOffer, configurator(theOffer, resolved)),
                "ghidra-mcp-launch");
        launcher.setDaemon(true);
        launcher.start();
        startWatchdog(offerName, launcher);
        var sb = new StringBuilder("Launch started for '" + offerName + "'. Poll debugger_status for progress.");
        if (!unmatched.isEmpty()) {
            sb.append("\nWARNING: ignored unknown parameter(s) ").append(unmatched)
                    .append(". Known parameters: ").append(params.keySet());
        }
        return sb.toString();
    }

    private void preflightPid(Map<String, String> resolved) {
        if (!rpm.available()) return;
        String pidStr = null;
        for (var e : resolved.entrySet()) {
            if (e.getKey().toUpperCase().endsWith("TARGET_PID")) {
                pidStr = e.getValue();
                break;
            }
        }
        if (pidStr == null || pidStr.isBlank()) return;
        int pid;
        try {
            pid = Integer.parseInt(pidStr.trim());
        } catch (NumberFormatException e) {
            return;
        }
        if (pid <= 0) return;
        int err = rpm.probeOpen(pid);
        if (err == ProcessMemory.ERROR_ACCESS_DENIED) {
            throw new IllegalStateException("Preflight: pid " + pid + " cannot be opened (ACCESS_DENIED). "
                    + "The target runs at a higher integrity level — relaunch Ghidra as Administrator. "
                    + "Refusing to launch dbgeng (it would hang ~90s then leave an orphan back-end). "
                    + "For the memory plane, use live_attach instead.");
        }
        if (err == 87) {
            throw new IllegalStateException("Preflight: pid " + pid + " not found (stale/wrong PID). "
                    + "Re-check the live PID (live_processes name=<exe>) and pass the current value.");
        }
    }

    private String backendLog() {
        var term = terminalText(lastResult);
        if (term.isBlank()) {
            return "No connector output captured (no launch has produced output yet, or it connected "
                    + "cleanly — check debugger_status). The live Terminal is also in the Ghidra GUI.";
        }
        return "--- connector output (tail) ---\n" + tail(term, TERMINAL_TAIL_CHARS * 4);
    }

    private static String resolveParamKey(Set<String> keys, String given) {
        if (keys.contains(given)) return given;
        var env = "env:" + given;
        if (keys.contains(env)) return env;
        for (var k : keys) {
            if (k.equalsIgnoreCase(given) || k.equalsIgnoreCase(env)) return k;
        }
        var lower = given.toLowerCase();
        for (var k : keys) {
            if (k.toLowerCase().endsWith(lower)) return k;
        }
        return null;
    }

    private TraceRmiLaunchOffer.LaunchConfigurator configurator(
            TraceRmiLaunchOffer offer, Map<String, String> resolved) {
        var params = offer.getParameters();
        return new TraceRmiLaunchOffer.LaunchConfigurator() {
            @Override
            public TraceRmiLaunchOffer.PromptMode getPromptMode() {
                return TraceRmiLaunchOffer.PromptMode.NEVER;
            }

            @Override
            public Map<String, ValStr<?>> configureLauncher(
                    TraceRmiLaunchOffer o, Map<String, ValStr<?>> defaults,
                    TraceRmiLaunchOffer.RelPrompt rel) {
                var m = new HashMap<>(defaults);
                for (var e : resolved.entrySet()) {
                    var lp = params.get(e.getKey());
                    if (lp != null) m.put(e.getKey(), lp.decode(e.getValue()));
                }
                return m;
            }
        };
    }

    private void runLaunch(String offerName, TraceRmiLaunchOffer offer,
            TraceRmiLaunchOffer.LaunchConfigurator cfg) {
        try {
            var result = offer.launchProgram(TaskMonitor.DUMMY, cfg);
            lastResult = result;
            if (result.trace() != null) {
                lastLaunch = "launched '" + offerName + "', trace=" + result.trace().getName();
                autoResume();
                return;
            }
            lastLaunch = describeIncomplete(offerName, result);
        } catch (Throwable e) {
            lastLaunch = "launch '" + offerName + "' failed: " + describeThrowable(e)
                    + diagnose(throwableText(e));
        }
    }

    private void startWatchdog(String offerName, Thread launcher) {
        var w = new Thread(() -> {
            try {
                launcher.join(LAUNCH_TIMEOUT_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (launcher.isAlive() && dbg.getCurrentTrace() == null) {
                var term = terminalText(lastResult);
                lastLaunch = "launch '" + offerName + "' still pending after "
                        + (LAUNCH_TIMEOUT_MS / 1000) + "s with no trace: the back-end started but never "
                        + "connected back to Ghidra's TraceRMI listener. MOST LIKELY the agent failed during "
                        + "start-up — call debugger_backend_log for the connector's own stdout/stderr (the real "
                        + "error). Common causes: missing python deps (ghidratrace/ghidradbg/pybag), WINDBG_DIR "
                        + "without dbgeng.dll, a stale/wrong PID, or a firewall blocking the loopback socket. "
                        + "FOR THE MEMORY PLANE (read/write/scan/freeze/pointer) skip dbgeng entirely: use "
                        + "live_attach name=<exe> — it OpenProcess's directly, no connector. Only the INVASIVE "
                        + "attach (OPT_ATTACH_FLAGS=0) can additionally hang on anti-debug swallowing the initial "
                        + "break; that does NOT apply to noninvasive (=5/=1)."
                        + (term.isBlank() ? "" : "\n--- connector output (tail) ---\n" + tail(term, TERMINAL_TAIL_CHARS));
            }
        }, "ghidra-mcp-launch-watchdog");
        w.setDaemon(true);
        w.start();
    }

    private String describeIncomplete(String offerName, TraceRmiLaunchOffer.LaunchResult result) {
        var sb = new StringBuilder();
        if (result.exception() != null) {
            sb.append("launch '").append(offerName).append("' failed: ")
                    .append(describeThrowable(result.exception()));
        } else if (result.connection() != null) {
            sb.append("launch '").append(offerName).append("' connected to Ghidra but no trace started. "
                    + "The back-end attached/launched yet did not begin a trace (often the target never "
                    + "hit an initial break). Try debugger_break, or stop the target, then retry.");
        } else {
            sb.append("launch '").append(offerName).append("' did not connect back to Ghidra. The "
                    + "connector started but never established a trace connection (it likely crashed or "
                    + "hung during start-up).");
        }
        var term = terminalText(result);
        if (!term.isBlank()) {
            sb.append("\n--- connector output (tail) ---\n").append(tail(term, TERMINAL_TAIL_CHARS));
        }
        var probe = (result.exception() != null ? throwableText(result.exception()) : "") + "\n" + term;
        return sb.append(diagnose(probe)).toString();
    }

    private void closeStaleResult() {
        var prev = lastResult;
        if (prev != null && prev.trace() == null) {
            try {
                prev.close();
            } catch (Exception ignored) {
            }
            lastResult = null;
        }
    }

    private static String describeThrowable(Throwable e) {
        if (e == null) return "(unknown error)";
        for (Throwable c = e; c != null; c = c.getCause()) {
            var m = c.getMessage();
            if (m != null && !m.isBlank()) return m + " (" + c.getClass().getSimpleName() + ")";
        }
        return e.getClass().getName();
    }

    private static String throwableText(Throwable e) {
        var sb = new StringBuilder();
        for (Throwable c = e; c != null; c = c.getCause()) {
            sb.append(c.getClass().getSimpleName());
            if (c.getMessage() != null) sb.append(": ").append(c.getMessage());
            sb.append('\n');
        }
        return sb.toString();
    }

    private static String terminalText(TraceRmiLaunchOffer.LaunchResult result) {
        if (result == null || result.sessions() == null) return "";
        var sb = new StringBuilder();
        for (var s : result.sessions().values()) {
            try {
                var c = s.content();
                if (c != null && !c.isBlank()) sb.append(c).append('\n');
            } catch (RuntimeException ignored) {
            }
        }
        return sb.toString();
    }

    private static String tail(String s, int n) {
        var t = s.strip();
        return t.length() <= n ? t : "..." + t.substring(t.length() - n);
    }

    private static String diagnose(String text) {
        if (text == null || text.isBlank()) return "";
        var t = text.toLowerCase();
        var sb = new StringBuilder();
        if (t.contains("access is denied") || t.contains("0n5") || t.contains("error 5")
                || t.contains("0x80070005")) {
            sb.append("\nHINT: access denied attaching to the target. It likely runs at a higher "
                    + "integrity level. Run Ghidra as Administrator with SeDebugPrivilege.");
        }
        if (t.contains("modulenotfounderror") || t.contains("importerror")
                || t.contains("no module named") || t.contains("253")) {
            sb.append("\nHINT: the connector Python is missing required packages. Install Ghidra's debug "
                    + "wheels (ghidratrace, ghidradbg, pybag) into that interpreter, or set the Python "
                    + "path parameter to one that has them.");
        }
        if (t.contains("windbg install directory not found") || t.contains("dbgeng.dll")
                || t.contains("dbghelp.dll")) {
            sb.append("\nHINT: dbgeng could not be located or loaded. Install WinDbg and set WINDBG_DIR "
                    + "to a folder containing dbgeng.dll, dbghelp.dll and dbgmodel.dll.");
        }
        if (t.contains("is not recognized") || t.contains("the system cannot find the file")
                || (t.contains("cannot find") && t.contains("python"))) {
            sb.append("\nHINT: the interpreter or launcher executable was not found. Pass the full path "
                    + "via the offer's Python/executable parameter.");
        }
        if (t.contains("cannot debug pid") || t.contains("no such process") || t.contains("0n87")) {
            sb.append("\nHINT: the target PID may be invalid or gone. Re-check the running PID and pass "
                    + "the current value via the offer's PID parameter.");
        }
        if (t.contains("accept timed out") || t.contains("sockettimeout") || t.contains("accept timeout")) {
            sb.append("\nHINT: the connector started but never connected back to Ghidra (the agent failed "
                    + "during start-up). Most common cause: a STALE PID — if the target was restarted its "
                    + "PID changed; re-check the live PID and pass the current value. Otherwise verify the "
                    + "Python path has ghidratrace/ghidradbg/pybag, WINDBG_DIR holds dbgeng.dll, and Ghidra "
                    + "runs elevated for an elevated target. The agent's own error is in the Ghidra Terminal "
                    + "window.");
        }
        return sb.toString();
    }

    private void autoResume() {
        for (int i = 0; i < 30 && !targetAlive(); i++) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        if (targetAlive() && dbg.resume()) {
            lastLaunch += " (auto-resumed)";
        }
    }

    private static Map<String, String> parseKv(String s) {
        var m = new LinkedHashMap<String, String>();
        if (s == null || s.isBlank()) return m;
        for (var part : s.split(",")) {
            int eq = part.indexOf('=');
            if (eq <= 0) continue;
            m.put(part.substring(0, eq).trim(), part.substring(eq + 1).trim());
        }
        return m;
    }

    private String freeze(String address, String hex) {
        if (hex == null || hex.isBlank()) throw new IllegalArgumentException("hex is required");
        var trace = dbg.getCurrentTrace();
        var da = liveAddr(address);
        frozen.put(da, Bufs.parseHex(hex));
        if (trace != null) enterTargetControl(trace);
        ensureFreezeTimer();
        return "Freezing " + Responses.addr(da) + " = " + hex + " (" + frozen.size() + " frozen)";
    }

    private String unfreeze(String address) {
        var da = liveAddr(address);
        boolean removed = frozen.remove(da) != null;
        if (frozen.isEmpty()) stopFreezeTimer();
        return removed
                ? "Unfrozen " + Responses.addr(da) : "Not frozen: " + Responses.addr(da);
    }

    private String listFrozen(Map<String, String> q) {
        var t = Responses.table(q, new String[]{"address", "hex"}, frozen.size());
        for (var e : frozen.entrySet()) t.row(Responses.addr(e.getKey()), Bufs.hex(e.getValue()));
        return t.build();
    }

    private synchronized void ensureFreezeTimer() {
        if (freezeTimer != null) return;
        var ex = Executors.newSingleThreadScheduledExecutor(r -> {
            var th = new Thread(r, "ghidra-mcp-freeze");
            th.setDaemon(true);
            return th;
        });
        ex.scheduleWithFixedDelay(this::applyFrozen, FREEZE_INTERVAL_MS, FREEZE_INTERVAL_MS,
                TimeUnit.MILLISECONDS);
        freezeTimer = ex;
    }

    private synchronized void stopFreezeTimer() {
        var ft = freezeTimer;
        if (ft != null) {
            ft.shutdownNow();
            freezeTimer = null;
        }
    }

    private void applyFrozen() {
        try {
            if (frozen.isEmpty()) {
                stopFreezeTimer();
                return;
            }
            var trace = dbg.getCurrentTrace();
            var pid = activePid();
            if (pid == null && (trace == null || !targetAlive())) {
                frozen.clear();
                stopFreezeTimer();
                return;
            }
            for (var e : frozen.entrySet()) {
                if (pid != null && rpm.write(pid, e.getKey().getOffset(), e.getValue())) continue;
                if (trace != null) {
                    try {
                        dbg.writeMemory(e.getKey(), e.getValue());
                    } catch (RuntimeException ignored) {
                    }
                }
            }
        } catch (RuntimeException ignored) {
        }
    }

    private String valueScan(Map<String, String> q) {
        var lc = liveCtx();
        var type = ScanValues.parseType(q.get("type"));
        var rawValue = q.get("value");
        if (rawValue == null || rawValue.isBlank()) throw new IllegalArgumentException("value is required");
        boolean bigEndian = lc.bigEndian();
        byte[] needle = ScanValues.encode(type, rawValue, bigEndian);
        boolean excludeModules = "1".equals(q.get("exclude_modules"));
        long budget = parseBudget(q.get("max_mb"));
        double tol = parseTol(q.get("tolerance"), type);
        double target = (type == ScanValues.Type.F32 || type == ScanValues.Type.F64)
                ? Double.parseDouble(rawValue.trim()) : 0;
        var pid = lc.pid();
        long snap;
        List<AddressRange> ranges;
        if (pid != null && rpm.available()) {
            snap = lc.trace() != null ? dbg.getCurrentSnap() : 0;
            ranges = rpmRanges(lc, excludeModules);
        } else if (lc.trace() != null) {
            syncPresent(lc.trace());
            invalidateCaches(lc.trace());
            snap = liveSnap(lc.trace());
            ranges = orderedRanges(lc.trace(), snap, excludeModules);
        } else {
            throw new IllegalStateException("No readable process handle for the live session");
        }
        if (ranges.isEmpty()) {
            throw new IllegalStateException("No scannable memory regions found "
                    + "(target not readable; check elevation/attach)");
        }
        int matchLen = (type == ScanValues.Type.STRING || type == ScanValues.Type.WSTRING
                || type == ScanValues.Type.BYTES) ? needle.length : type.width;
        var session = new ScanSession(type, bigEndian, target, matchLen);
        evictExpiredScans();
        evictOldScans();
        var id = "scan" + scanSeq.incrementAndGet();
        scans.put(id, session);
        scanExec.submit(() -> runScan(session, lc, snap, ranges, needle, type, bigEndian, budget, tol, pid));
        return "scan_id=" + id + " (scanning " + ranges.size() + " ranges, budget="
                + (budget >> 20) + "MB; poll scan_results)";
    }

    private List<AddressRange> rpmRanges(LiveCtx lc, boolean excludeModules) {
        var space = lc.space();
        int pid = lc.pid();
        var moduleSet = new AddressSet();
        if (excludeModules) {
            if (lc.trace() != null) {
                long snap = liveSnap(lc.trace());
                for (TraceModule m : lc.trace().getModuleManager().getAllModules()) {
                    var r = m.getRange(snap);
                    if (r != null) moduleSet.add(r);
                }
            } else {
                long maxOff = space.getMaxAddress().getOffset();
                for (var m : rpm.modules(pid)) {
                    long end = m.base() + m.size() - 1;
                    if (Long.compareUnsigned(end, maxOff) > 0) continue;
                    moduleSet.add(new AddressRangeImpl(space.getAddress(m.base()),
                            space.getAddress(end)));
                }
            }
        }
        var writable = new ArrayList<AddressRange>();
        var readOnly = new ArrayList<AddressRange>();
        for (var region : rpm.enumerateRegions(pid)) {
            var min = space.getAddress(region.base());
            var max = space.getAddress(region.base() + region.size() - 1);
            if (excludeModules && moduleSet.intersects(min, max)) continue;
            var range = new AddressRangeImpl(min, max);
            (region.writable() ? writable : readOnly).add(range);
        }
        writable.addAll(readOnly);
        return writable;
    }

    private List<AddressRange> orderedRanges(Trace trace, long snap, boolean excludeModules) {
        var modules = new AddressSet();
        for (TraceModule m : trace.getModuleManager().getAllModules()) {
            var r = m.getRange(snap);
            if (r != null) modules.add(r);
        }
        var writable = new ArrayList<AddressRange>();
        var readOnly = new ArrayList<AddressRange>();
        var moduleRanges = new ArrayList<AddressRange>();
        for (TraceMemoryRegion region : trace.getMemoryManager().getRegionsAtSnap(snap)) {
            if (!region.isRead(snap)) continue;
            var r = region.getRange(snap);
            if (r == null) continue;
            if (modules.intersects(r.getMinAddress(), r.getMaxAddress())) {
                moduleRanges.add(r);
            } else if (region.isWrite(snap)) {
                writable.add(r);
            } else {
                readOnly.add(r);
            }
        }
        var ordered = new ArrayList<>(writable);
        ordered.addAll(readOnly);
        if (!excludeModules) ordered.addAll(moduleRanges);
        return ordered;
    }

    private void evictOldScans() {
        while (scans.size() >= MAX_SCAN_SESSIONS) {
            scans.keySet().stream()
                    .min(Comparator.comparingInt(k -> Integer.parseInt(k.substring(4))))
                    .ifPresent(scans::remove);
        }
    }

    private void evictExpiredScans() {
        long now = System.currentTimeMillis();
        scans.values().removeIf(s -> s.done && now - s.lastAccess > SCAN_TTL_MS);
    }

    private byte[] readScanChunk(LiveCtx lc, long snap, Address addr, int want, Integer pid) {
        var fast = rpmRead(pid, addr, want);
        if (fast != null) return fast;
        var trace = lc.trace();
        if (trace == null) return null;
        try {
            var range = new AddressRangeImpl(addr, addr.add(want - 1L));
            var mem = trace.getMemoryManager();
            if (mem.isKnown(snap, range)) {
                var buf = ByteBuffer.allocate(want);
                int n = mem.getBytes(snap, addr, buf);
                if (n == want) return buf.array();
                if (n > 0) return Arrays.copyOf(buf.array(), n);
            }
        } catch (RuntimeException ignored) {
        }
        try {
            return dbg.readMemory(trace, snap, addr, want, TaskMonitor.DUMMY);
        } catch (Exception e) {
            return null;
        }
    }

    private void runScan(ScanSession session, LiveCtx lc, long snap, List<AddressRange> ranges,
            byte[] needle, ScanValues.Type type, boolean bigEndian, long budget, double tol, Integer pid) {
        int step = step(type);
        boolean floatTol = tol > 0 && (type == ScanValues.Type.F32 || type == ScanValues.Type.F64);
        long scanned = 0;
        try {
            outer:
            for (var range : ranges) {
                long len = range.getLength();
                if (len <= 0) continue;
                Address base = range.getMinAddress();
                long off = 0;
                while (off < len) {
                    if (scanned >= budget) {
                        session.budgetHit = true;
                        break outer;
                    }
                    int want = (int) Math.min(SCAN_CHUNK, Math.min(len - off, budget - scanned));
                    byte[] data = readScanChunk(lc, snap, base.add(off), want, pid);
                    if (data == null || data.length == 0) {
                        off += want;
                        continue;
                    }
                    scanned += data.length;
                    session.scannedBytes = scanned;
                    int limit = data.length - needle.length;
                    for (int i = 0; i <= limit; i += step) {
                        boolean hit = floatTol
                                ? Math.abs(ScanValues.decodeNumber(type, data, i, bigEndian) - session.target) <= tol
                                : regionEquals(data, i, needle);
                        if (hit) {
                            Address ha = base.add(off + i);
                            if (session.stringy()) {
                                int end = Math.min(i + session.matchLen, data.length);
                                session.add(ha, 0, Arrays.copyOfRange(data, i, end));
                            } else {
                                session.add(ha, ScanValues.decodeNumber(type, data, i, bigEndian), null);
                            }
                            if (session.size() >= SCAN_MAX_HITS) return;
                        }
                    }
                    off += data.length;
                }
            }
        } finally {
            session.touch();
            session.done = true;
        }
    }

    private static long parseBudget(String s) {
        if (s == null || s.isBlank()) return DEFAULT_SCAN_BUDGET;
        long mb = Long.parseLong(s.trim());
        if (mb <= 0 || mb > MAX_SCAN_BUDGET_MB) {
            throw new IllegalArgumentException("max_mb must be 1.." + MAX_SCAN_BUDGET_MB);
        }
        return mb << 20;
    }

    private static double parseTol(String s, ScanValues.Type type) {
        if (s == null || s.isBlank()) return 0;
        if (type != ScanValues.Type.F32 && type != ScanValues.Type.F64) {
            throw new IllegalArgumentException("tolerance is only valid for f32/f64 scans");
        }
        return Double.parseDouble(s.trim());
    }

    private Map<Address, byte[]> bulkReadHits(List<Address> addrs, int width) {
        var result = new HashMap<Address, byte[]>();
        if (addrs.isEmpty()) return result;
        var lc = liveCtx();
        var trace = lc.trace();
        long snap = trace != null ? liveSnap(trace) : 0;
        var pid = lc.pid();
        var sorted = new ArrayList<>(addrs);
        sorted.sort(null);
        int n = sorted.size();
        int i = 0;
        while (i < n) {
            Address spanStart = sorted.get(i);
            int j = i;
            while (j + 1 < n) {
                Address next = sorted.get(j + 1);
                if (!next.getAddressSpace().equals(spanStart.getAddressSpace())) break;
                if (next.subtract(spanStart) + width > SCAN_CHUNK) break;
                j++;
            }
            int spanLen = (int) (sorted.get(j).subtract(spanStart) + width);
            byte[] data = rpmRead(pid, spanStart, spanLen);
            if (data == null && trace != null) {
                try {
                    data = dbg.readMemory(trace, snap, spanStart, spanLen, TaskMonitor.DUMMY);
                } catch (Exception e) {
                    data = null;
                }
            }
            if (data != null) {
                for (int k = i; k <= j; k++) {
                    Address a = sorted.get(k);
                    int off = (int) a.subtract(spanStart);
                    if (off + width <= data.length) {
                        var slice = new byte[width];
                        System.arraycopy(data, off, slice, 0, width);
                        result.put(a, slice);
                    }
                }
            }
            i = j + 1;
        }
        return result;
    }

    private String nextScan(Map<String, String> p) {
        evictExpiredScans();
        var id = p.get("scan_id");
        var session = scans.get(id);
        if (session == null) throw new IllegalArgumentException("unknown scan_id (run value_scan first)");
        session.touch();
        liveCtx();
        if (!session.done) {
            return "scan " + id + " still running (" + (session.scannedBytes >> 20)
                    + "MB, " + session.size() + " hits so far). Wait for status=done, then retry.";
        }
        var cmp = p.getOrDefault("comparator", "exact");
        var value = p.get("value");
        int width = session.type.width;
        byte[] needle = (value != null && !value.isBlank())
                ? ScanValues.encode(session.type, value, session.bigEndian) : null;
        var kept = new ArrayList<Address>();
        var newLast = new HashMap<Address, Double>();
        var newLastBytes = new HashMap<Address, byte[]>();
        boolean stringy = session.stringy();
        int readLen = stringy
                ? Math.max(session.matchLen, needle != null ? needle.length : 0)
                : (needle != null ? Math.max(width, needle.length) : width);
        var reads = bulkReadHits(session.hits, readLen);
        for (var a : session.hits) {
            byte[] cur = reads.get(a);
            if (cur == null) continue;
            boolean keep;
            if (stringy) {
                byte[] prevB = session.lastBytes.get(a);
                int n = session.matchLen;
                keep = switch (cmp) {
                    case "exact", "value" -> needle != null && regionEquals(cur, 0, needle);
                    case "changed" -> prevB != null && cur.length >= n && !regionEqualsN(cur, prevB, n);
                    case "unchanged" -> prevB != null && cur.length >= n && regionEqualsN(cur, prevB, n);
                    default -> throw new IllegalArgumentException("string/bytes scans support comparator "
                            + "exact|changed|unchanged (not increased/decreased)");
                };
                if (keep) {
                    kept.add(a);
                    newLastBytes.put(a, Arrays.copyOf(cur, Math.min(n, cur.length)));
                }
            } else {
                if (cur.length < width) continue;
                double curNum = ScanValues.decodeNumber(session.type, cur, session.bigEndian);
                Double prev = session.last.get(a);
                keep = switch (cmp) {
                    case "exact", "value" -> needle != null && regionEquals(cur, 0, needle);
                    case "changed" -> prev != null && curNum != prev;
                    case "unchanged" -> prev != null && curNum == prev;
                    case "increased" -> prev != null && curNum > prev;
                    case "decreased" -> prev != null && curNum < prev;
                    default -> throw new IllegalArgumentException(
                            "comparator: exact|changed|unchanged|increased|decreased");
                };
                if (keep) {
                    kept.add(a);
                    newLast.put(a, curNum);
                }
            }
        }
        session.hits = kept;
        session.last = newLast;
        session.lastBytes = newLastBytes;
        return "scan_id=" + id + "\nhits=" + kept.size() + "\n" + sampleHits(session);
    }

    private String scanResults(Map<String, String> q) {
        evictExpiredScans();
        var session = scans.get(q.get("scan_id"));
        if (session == null) throw new IllegalArgumentException("unknown scan_id");
        session.touch();
        int limit = Http.parseIntOrDefault(q.get("limit"), 100);
        var t = Responses.table(q, new String[]{"dynamic", "static", "value"},
                Math.min(limit, session.size()));
        var shown = session.snapshot();
        if (shown.size() > limit) shown = shown.subList(0, limit);
        var reads = bulkReadHits(shown, session.type.width);
        boolean noTrace = dbg.getCurrentTrace() == null;
        var prog = ctx.currentProgram();
        for (var a : shown) {
            var sa = safeToStatic(a);
            if (sa == null && noTrace && prog != null && prog.getMemory().contains(a)) sa = a;
            var b = reads.get(a);
            t.row(Responses.addr(a), sa == null ? "" : Responses.addr(sa),
                    b == null ? "?" : formatVal(session, b));
        }
        return "# status=" + (session.done ? "done" : "running")
                + ", scanned=" + (session.scannedBytes >> 20) + "MB, hits=" + session.size()
                + (session.budgetHit ? ", coverage=INCOMPLETE (budget hit; raise max_mb)" : "") + "\n"
                + t.total(session.size()).build();
    }

    private String scanClose(String id) {
        if (id == null || id.isBlank()) throw new IllegalArgumentException("scan_id is required");
        return scans.remove(id) != null
                ? "Closed " + id + " (" + scans.size() + " sessions remain)"
                : "Unknown scan_id: " + id;
    }

    private String sampleHits(ScanSession s) {
        var sb = new StringBuilder("# first hits (dynamic):");
        int n = Math.min(20, s.hits.size());
        for (int i = 0; i < n; i++) sb.append(i == 0 ? " " : ", ").append(Responses.addr(s.hits.get(i)));
        return sb.toString();
    }

    private String formatVal(ScanSession s, byte[] b) {
        if (s.type == ScanValues.Type.STRING || s.type == ScanValues.Type.BYTES) return Bufs.hex(b);
        double d = ScanValues.decodeNumber(s.type, b, s.bigEndian);
        return d == Math.rint(d) ? Long.toString((long) d) : Double.toString(d);
    }

    private record StructField(String name, String type, int size, long offset) {}

    private static List<StructField> parseStructSchema(String schema, int ptr) {
        var out = new ArrayList<StructField>();
        for (var raw : schema.split("[\\r\\n,]+")) {
            var line = raw.trim();
            if (line.isEmpty()) continue;
            var m = STRUCT_FIELD.matcher(line);
            if (!m.matches()) {
                throw new IllegalArgumentException("invalid schema field: " + line);
            }
            var type = m.group(2).toLowerCase();
            int size = structFieldSize(type, m.group(3), ptr);
            out.add(new StructField(m.group(1), type, size, Http.parseFlexibleLong(m.group(4), 0)));
        }
        if (out.isEmpty()) throw new IllegalArgumentException("schema has no fields");
        return out;
    }

    private static int structFieldSize(String type, String len, int ptr) {
        return switch (type) {
            case "ptr" -> ptr;
            case "u8", "i8" -> 1;
            case "u16", "i16" -> 2;
            case "u32", "i32", "f32" -> 4;
            case "u64", "i64", "f64" -> 8;
            case "vec3" -> 12;
            case "mat3x4" -> 48;
            case "string", "bytes" -> {
                if (len == null) throw new IllegalArgumentException(type + " fields need [length]");
                int n = Integer.parseInt(len);
                if (n <= 0 || n > 65536) throw new IllegalArgumentException(type + " length must be 1..65536");
                yield n;
            }
            default -> throw new IllegalArgumentException("unsupported struct field type: " + type);
        };
    }

    private static String decodeStructField(StructField f, byte[] b, boolean bigEndian, int ptr) {
        return switch (f.type()) {
            case "ptr" -> "0x" + Long.toHexString(unsigned(b, ptr, bigEndian));
            case "u8", "u16", "u32", "u64" -> Long.toUnsignedString(unsigned(b, f.size(), bigEndian));
            case "i8", "i16", "i32", "i64" -> Long.toString(signed(b, f.size(), bigEndian));
            case "f32" -> Float.toString(Float.intBitsToFloat((int) unsigned(b, 4, bigEndian)));
            case "f64" -> Double.toString(Double.longBitsToDouble(unsigned(b, 8, bigEndian)));
            case "vec3" -> Float.toString(f32(b, 0, bigEndian)) + ","
                    + f32(b, 4, bigEndian) + "," + f32(b, 8, bigEndian);
            case "mat3x4" -> mat3x4(b, bigEndian);
            case "string" -> cString(b);
            case "bytes" -> Bufs.hex(b);
            default -> "?";
        };
    }

    private static long unsigned(byte[] b, int n, boolean bigEndian) {
        long v = 0;
        int limit = Math.min(n, b.length);
        if (bigEndian) {
            for (int i = 0; i < limit; i++) v = (v << 8) | (b[i] & 0xffL);
        } else {
            for (int i = limit - 1; i >= 0; i--) v = (v << 8) | (b[i] & 0xffL);
        }
        return v;
    }

    private static long signed(byte[] b, int n, boolean bigEndian) {
        long v = unsigned(b, n, bigEndian);
        int shift = 64 - n * 8;
        return (v << shift) >> shift;
    }

    private static float f32(byte[] b, int off, boolean bigEndian) {
        var slice = Arrays.copyOfRange(b, off, off + 4);
        return Float.intBitsToFloat((int) unsigned(slice, 4, bigEndian));
    }

    private static String mat3x4(byte[] b, boolean bigEndian) {
        var sb = new StringBuilder();
        for (int i = 0; i < 12; i++) {
            if (i > 0) sb.append(',');
            sb.append(f32(b, i * 4, bigEndian));
        }
        return sb.toString();
    }

    private static String cString(byte[] b) {
        int n = 0;
        while (n < b.length && b[n] != 0) n++;
        return new String(b, 0, n, StandardCharsets.US_ASCII);
    }

    private static int step(ScanValues.Type t) {
        return switch (t) {
            case STRING, WSTRING, BYTES -> 1;
            default -> t.width;
        };
    }

    private static boolean regionEquals(byte[] data, int off, byte[] needle) {
        if (off + needle.length > data.length) return false;
        for (int i = 0; i < needle.length; i++) {
            if (data[off + i] != needle[i]) return false;
        }
        return true;
    }

    private static boolean regionEqualsN(byte[] a, byte[] b, int n) {
        if (a.length < n || b.length < n) return false;
        for (int i = 0; i < n; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    private static final class ScanSession {
        final ScanValues.Type type;
        final boolean bigEndian;
        final double target;
        final int matchLen;
        volatile boolean done = false;
        volatile boolean budgetHit = false;
        volatile long scannedBytes = 0;
        volatile long lastAccess = System.currentTimeMillis();
        List<Address> hits = new ArrayList<>();
        Map<Address, Double> last = new HashMap<>();
        Map<Address, byte[]> lastBytes = new HashMap<>();

        ScanSession(ScanValues.Type type, boolean bigEndian, double target, int matchLen) {
            this.type = type;
            this.bigEndian = bigEndian;
            this.target = target;
            this.matchLen = matchLen;
        }

        boolean stringy() {
            return type == ScanValues.Type.STRING || type == ScanValues.Type.WSTRING
                    || type == ScanValues.Type.BYTES;
        }

        void touch() {
            lastAccess = System.currentTimeMillis();
        }

        synchronized void add(Address a, double value, byte[] bytes) {
            hits.add(a);
            last.put(a, value);
            if (bytes != null) lastBytes.put(a, bytes);
        }

        synchronized List<Address> snapshot() {
            return new ArrayList<>(hits);
        }

        int size() {
            return hits.size();
        }
    }
}
