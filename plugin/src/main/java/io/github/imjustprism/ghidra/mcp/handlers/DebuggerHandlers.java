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
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.ProcessMemory;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.ScanValues;

import java.math.BigInteger;
import java.nio.ByteBuffer;
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

public final class DebuggerHandlers {

    private static final String NO_SESSION =
            "No live debug session. In Ghidra: Debugger -> Launch or attach a "
                    + "target (e.g. local-dbgeng, attach by PID), then retry.";

    private static final String NO_DEBUGGER =
            "Debugger services not loaded in this Ghidra tool. Open the program in "
                    + "the Debugger tool (or add the Debugger plugins to this tool), "
                    + "then launch/attach a target.";

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
    private volatile TraceRmiLaunchOffer.LaunchResult lastResult;

    public DebuggerHandlers(PluginContext ctx) {
        this.ctx = ctx;
        var tool = ctx.tool();
        this.dbg = () -> {
            var pm = tool.getService(ProgramManager.class);
            var prog = pm == null ? null : pm.getCurrentProgram();
            return new GhidraState(tool, tool.getProject(), prog, null, null, null);
        };
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
        routes.postForm("/debugger_launch", p -> launch(p.get("offer"), p.get("args")));
        routes.postForm("/freeze_value", p -> freeze(p.get("address"), p.get("hex")));
        routes.postForm("/unfreeze_value", p -> unfreeze(p.get("address")));
        routes.getQuery("/list_frozen", this::listFrozen);
        routes.getQuery("/value_scan", this::valueScan);
        routes.postForm("/next_scan", this::nextScan);
        routes.getQuery("/scan_results", this::scanResults);
        routes.postForm("/scan_close", p -> scanClose(p.get("scan_id")));
    }

    public void close() {
        scanExec.shutdownNow();
        var ft = freezeTimer;
        if (ft != null) ft.shutdownNow();
        rpm.close();
    }

    private Trace requireTrace() {
        if (ctx.service(DebuggerTraceManagerService.class) == null) {
            throw new IllegalArgumentException(NO_DEBUGGER);
        }
        var t = dbg.getCurrentTrace();
        if (t == null) throw new IllegalArgumentException(NO_SESSION);
        return t;
    }

    private static int parseLen(String s) {
        int len = s == null ? 64 : Integer.parseInt(s);
        if (len <= 0 || len > 65536) throw new IllegalArgumentException("length must be 1..65536");
        return len;
    }

    private static long parseOffset(String s) {
        if (s == null || s.isBlank()) throw new IllegalArgumentException("address is required");
        var v = s.trim();
        boolean hex = v.startsWith("0x") || v.startsWith("0X");
        return Long.parseUnsignedLong(hex ? v.substring(2) : v, 16);
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
        if (!lastLaunch.isBlank() && dbg.getCurrentTrace() == null) return lastLaunch;
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
        var thread = dbg.getCurrentThread();
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

    private Address safeToStatic(Address dyn) {
        try {
            return dbg.translateDynamicToStatic(dyn);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private String registers(java.util.Map<String, String> q) {
        var trace = requireTrace();
        var thread = dbg.getCurrentThread();
        if (thread == null) throw new IllegalArgumentException("No current thread (attach and stop a target first)");
        var platform = dbg.getCurrentPlatform();
        long snap = dbg.getCurrentSnap();
        int frame = dbg.getCurrentFrame();
        var regs = new java.util.ArrayList<Register>();
        for (Register r : trace.getBaseLanguage().getRegisters()) {
            if (r.isBaseRegister() && !r.isProcessorContext()) regs.add(r);
        }
        var values = dbg.readRegisters(platform, thread, frame, snap, regs);
        var t = Responses.table(q, new String[]{"register", "value"}, regs.size());
        for (RegisterValue rv : values) {
            if (rv == null) continue;
            BigInteger v = rv.getUnsignedValue();
            t.row(rv.getRegister().getName(), v == null ? "" : v.toString(16));
        }
        return t.build();
    }

    private String readMemory(String address, int length) {
        var trace = requireTrace();
        var da = dynAddr(address);
        byte[] b = rpmRead(livePid(trace), da, length);
        if (b == null) {
            syncPresent(trace);
            try {
                invalidateCaches(trace);
                b = dbg.readMemory(trace, liveSnap(trace), da, length, TaskMonitor.DUMMY);
            } catch (Exception e) {
                throw new IllegalStateException("Error reading live memory at "
                        + Responses.addr(da) + ": " + e.getMessage(), e);
            }
        }
        return Responses.addr(da) + "\t" + b.length + "\t" + Bufs.hex(b);
    }

    private String breakpoints(java.util.Map<String, String> q) {
        var t = Responses.table(q, new String[]{"address", "name", "kinds", "length"}, 8);
        for (LogicalBreakpoint b : dbg.getAllBreakpoints()) {
            t.row(Responses.addr(b.getAddress()), b.getName(), b.getKinds(), b.getLength());
        }
        return t.build();
    }

    private String staticToDynamic(String address) {
        requireTrace();
        var da = dbg.translateStaticToDynamic(staticAddr(address));
        return da == null ? "No mapping for static address " + address : Responses.addr(da);
    }

    private String dynamicToStatic(String address) {
        var trace = requireTrace();
        var da = trace.getBaseLanguage().getDefaultSpace().getAddress(parseOffset(address));
        var sa = safeToStatic(da);
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
        closeStaleResult();
        lastLaunch = "launching '" + offerName + "'...";
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
                lastLaunch = "launch '" + offerName + "' still pending after "
                        + (LAUNCH_TIMEOUT_MS / 1000) + "s with no trace. The connector is running but "
                        + "has not started a trace, usually because the back-end is waiting on the "
                        + "target (e.g. a dbgeng attach that produced no initial break) or is blocked. "
                        + "Inspect the connector terminal in Ghidra. If the target runs elevated, run "
                        + "Ghidra as Administrator.";
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
        var trace = requireTrace();
        var da = dynAddr(address);
        frozen.put(da, Bufs.parseHex(hex));
        enterTargetControl(trace);
        ensureFreezeTimer();
        return "Freezing " + Responses.addr(da) + " = " + hex + " (" + frozen.size() + " frozen)";
    }

    private String unfreeze(String address) {
        var da = dynAddr(address);
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
            if (trace == null || !targetAlive()) {
                frozen.clear();
                stopFreezeTimer();
                return;
            }
            var pid = livePid(trace);
            for (var e : frozen.entrySet()) {
                if (pid != null && rpm.write(pid, e.getKey().getOffset(), e.getValue())) continue;
                try {
                    dbg.writeMemory(e.getKey(), e.getValue());
                } catch (RuntimeException ignored) {
                }
            }
        } catch (RuntimeException ignored) {
        }
    }

    private String valueScan(Map<String, String> q) {
        var trace = requireTrace();
        var type = ScanValues.parseType(q.get("type"));
        var rawValue = q.get("value");
        if (rawValue == null || rawValue.isBlank()) throw new IllegalArgumentException("value is required");
        boolean bigEndian = trace.getBaseLanguage().isBigEndian();
        byte[] needle = ScanValues.encode(type, rawValue, bigEndian);
        boolean excludeModules = "1".equals(q.get("exclude_modules"));
        long budget = parseBudget(q.get("max_mb"));
        double tol = parseTol(q.get("tolerance"), type);
        double target = (type == ScanValues.Type.F32 || type == ScanValues.Type.F64)
                ? Double.parseDouble(rawValue.trim()) : 0;
        var pid = livePid(trace);
        long snap;
        List<AddressRange> ranges;
        if (pid != null && rpm.available()) {
            snap = dbg.getCurrentSnap();
            ranges = rpmRanges(trace, pid, excludeModules);
        } else {
            syncPresent(trace);
            invalidateCaches(trace);
            snap = liveSnap(trace);
            ranges = orderedRanges(trace, snap, excludeModules);
        }
        if (ranges.isEmpty()) {
            throw new IllegalStateException("No scannable memory regions found "
                    + "(target not readable; check elevation/attach)");
        }
        var session = new ScanSession(type, bigEndian, target);
        evictExpiredScans();
        evictOldScans();
        var id = "scan" + scanSeq.incrementAndGet();
        scans.put(id, session);
        scanExec.submit(() -> runScan(session, trace, snap, ranges, needle, type, bigEndian, budget, tol, pid));
        return "scan_id=" + id + " (scanning " + ranges.size() + " ranges, budget="
                + (budget >> 20) + "MB; poll scan_results)";
    }

    private List<AddressRange> rpmRanges(Trace trace, int pid, boolean excludeModules) {
        var space = trace.getBaseLanguage().getDefaultSpace();
        var moduleSet = new AddressSet();
        if (excludeModules) {
            long snap = liveSnap(trace);
            for (TraceModule m : trace.getModuleManager().getAllModules()) {
                var r = m.getRange(snap);
                if (r != null) moduleSet.add(r);
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

    private byte[] readScanChunk(Trace trace, long snap, Address addr, int want, Integer pid) {
        var fast = rpmRead(pid, addr, want);
        if (fast != null) return fast;
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

    private void runScan(ScanSession session, Trace trace, long snap, List<AddressRange> ranges,
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
                    byte[] data = readScanChunk(trace, snap, base.add(off), want, pid);
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
                            session.add(base.add(off + i), ScanValues.decodeNumber(type, data, i, bigEndian));
                            if (session.size() >= SCAN_MAX_HITS) return;
                        }
                    }
                    off += data.length;
                }
            }
        } finally {
            session.done = true;
            session.touch();
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
        var trace = requireTrace();
        long snap = liveSnap(trace);
        var pid = livePid(trace);
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
            if (data == null) {
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
        var id = p.get("scan_id");
        var session = scans.get(id);
        if (session == null) throw new IllegalArgumentException("unknown scan_id (run value_scan first)");
        session.touch();
        evictExpiredScans();
        requireTrace();
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
        int readLen = needle != null ? Math.max(width, needle.length) : width;
        var reads = bulkReadHits(session.hits, readLen);
        for (var a : session.hits) {
            byte[] cur = reads.get(a);
            if (cur == null || cur.length < width) continue;
            double curNum = ScanValues.decodeNumber(session.type, cur, session.bigEndian);
            Double prev = session.last.get(a);
            boolean keep = switch (cmp) {
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
        session.hits = kept;
        session.last = newLast;
        return "scan_id=" + id + "\nhits=" + kept.size() + "\n" + sampleHits(session);
    }

    private String scanResults(Map<String, String> q) {
        var session = scans.get(q.get("scan_id"));
        if (session == null) throw new IllegalArgumentException("unknown scan_id");
        session.touch();
        evictExpiredScans();
        int limit = Http.parseIntOrDefault(q.get("limit"), 100);
        var t = Responses.table(q, new String[]{"dynamic", "static", "value"},
                Math.min(limit, session.size()));
        var shown = session.snapshot();
        if (shown.size() > limit) shown = shown.subList(0, limit);
        var reads = bulkReadHits(shown, session.type.width);
        for (var a : shown) {
            var sa = safeToStatic(a);
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

    private static final class ScanSession {
        final ScanValues.Type type;
        final boolean bigEndian;
        final double target;
        volatile boolean done = false;
        volatile boolean budgetHit = false;
        volatile long scannedBytes = 0;
        volatile long lastAccess = System.currentTimeMillis();
        List<Address> hits = new ArrayList<>();
        Map<Address, Double> last = new HashMap<>();

        ScanSession(ScanValues.Type type, boolean bigEndian, double target) {
            this.type = type;
            this.bigEndian = bigEndian;
            this.target = target;
        }

        void touch() {
            lastAccess = System.currentTimeMillis();
        }

        synchronized void add(Address a, double value) {
            hits.add(a);
            last.put(a, value);
        }

        synchronized List<Address> snapshot() {
            return new ArrayList<>(hits);
        }

        int size() {
            return hits.size();
        }
    }
}
