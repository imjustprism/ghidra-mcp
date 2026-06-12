package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.app.script.GhidraState;
import ghidra.app.services.DebuggerControlService;
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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.task.TaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.Http;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.Bufs;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.ScanValues;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    private final PluginContext ctx;
    private final FlatDebuggerAPI dbg;
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
    }

    public void close() {
        scanExec.shutdownNow();
        var ft = freezeTimer;
        if (ft != null) ft.shutdownNow();
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
                throw new IllegalArgumentException(s + " is a program address with no live module"
                        + " mapping yet (stop the target so modules sync, or pass a raw dynamic"
                        + " offset like 0x7ff...). Refusing to read/write a raw static offset.");
            }
        }
        return trace.getBaseLanguage().getDefaultSpace().getAddress(parseOffset(s));
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
        if (thread == null) return "No current thread";
        long snap = dbg.getCurrentSnap();
        TraceStack stack = trace.getStackManager().getLatestStack(thread, snap);
        if (stack == null) return "No stack for current thread at snap " + snap;
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
        if (thread == null) return "No current thread";
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
        var da = dynAddr(address);
        try {
            byte[] b = dbg.readMemory(da, length, TaskMonitor.DUMMY);
            return Responses.addr(da) + "\t" + b.length + "\t" + Bufs.hex(b);
        } catch (Exception e) {
            return "Error reading live memory at " + Responses.addr(da) + ": " + e.getMessage();
        }
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
        requireTrace();
        boolean ok = switch (op) {
            case "resume" -> dbg.resume();
            case "step_into" -> dbg.stepInto();
            case "step_over" -> dbg.stepOver();
            case "interrupt" -> dbg.interrupt();
            default -> throw new IllegalArgumentException("unknown control op: " + op);
        };
        return ok ? op + " ok (snap=" + dbg.getCurrentSnap() + ")"
                : op + " failed (target not alive or busy?)";
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
        enterTargetControl(trace);
        boolean ok = dbg.writeMemory(da, bytes);
        return ok ? "Wrote " + bytes.length + " byte(s) to " + Responses.addr(da)
                : "Write failed at " + Responses.addr(da) + " (target not alive?)";
    }

    private String writeRegister(String register, String value) {
        if (register == null || register.isBlank()) throw new IllegalArgumentException("register is required");
        if (value == null || value.isBlank()) throw new IllegalArgumentException("value is required");
        var trace = requireTrace();
        BigInteger v = parseBigInt(value);
        enterTargetControl(trace);
        boolean ok = dbg.writeRegister(register, v);
        return ok ? "Wrote " + register + "=0x" + v.toString(16)
                : "Write failed for register " + register + " (target not alive or bad name?)";
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
        if (svc == null) return "Launcher service unavailable";
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
        if (svc == null) return "Launcher service unavailable";
        TraceRmiLaunchOffer offer = null;
        for (var o : svc.getOffers(prog)) {
            if (o.getConfigName().equals(offerName)) {
                offer = o;
                break;
            }
        }
        if (offer == null) return "No offer '" + offerName + "'. See debugger_list_offers.";
        var overrides = parseKv(args);
        var theOffer = offer;
        var cfg = new TraceRmiLaunchOffer.LaunchConfigurator() {
            @Override
            public TraceRmiLaunchOffer.PromptMode getPromptMode() {
                return TraceRmiLaunchOffer.PromptMode.NEVER;
            }

            @Override
            public Map<String, ValStr<?>> configureLauncher(
                    TraceRmiLaunchOffer o, Map<String, ValStr<?>> defaults,
                    TraceRmiLaunchOffer.RelPrompt rel) {
                var m = new HashMap<>(defaults);
                var params = theOffer.getParameters();
                for (var e : overrides.entrySet()) {
                    var lp = params.get(e.getKey());
                    if (lp != null) m.put(e.getKey(), lp.decode(e.getValue()));
                }
                return m;
            }
        };
        lastLaunch = "launching '" + offerName + "'...";
        var launcher = new Thread(() -> {
            try {
                var result = theOffer.launchProgram(TaskMonitor.DUMMY, cfg);
                if (result.exception() != null) {
                    lastLaunch = "launch reported: " + result.exception().getMessage();
                    return;
                }
                var tr = result.trace();
                lastLaunch = "launched '" + offerName + "'"
                        + (tr != null ? ", trace=" + tr.getName() : "");
                autoResume();
            } catch (Exception e) {
                lastLaunch = "launch failed: " + e.getMessage();
            }
        }, "ghidra-mcp-launch");
        launcher.setDaemon(true);
        launcher.start();
        return "Launch started for '" + offerName + "'. Poll debugger_status for progress.";
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
        requireTrace();
        var da = dynAddr(address);
        frozen.put(da, Bufs.parseHex(hex));
        ensureFreezeTimer();
        return "Freezing " + Responses.addr(da) + " = " + hex + " (" + frozen.size() + " frozen)";
    }

    private String unfreeze(String address) {
        var da = dynAddr(address);
        return frozen.remove(da) != null
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

    private void applyFrozen() {
        if (frozen.isEmpty()) return;
        try {
            var trace = dbg.getCurrentTrace();
            if (trace == null || !targetAlive()) return;
            enterTargetControl(trace);
            for (var e : frozen.entrySet()) {
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
        long snap = dbg.getCurrentSnap();
        var ranges = orderedRanges(trace, snap, excludeModules);
        var session = new ScanSession(type, bigEndian, target);
        var id = "scan" + scanSeq.incrementAndGet();
        scans.put(id, session);
        scanExec.submit(() -> runScan(session, ranges, needle, type, bigEndian, budget, tol));
        return "scan_id=" + id + " (scanning " + ranges.size() + " ranges, budget="
                + (budget >> 20) + "MB; poll scan_results)";
    }

    private List<AddressRange> orderedRanges(Trace trace, long snap, boolean excludeModules) {
        var all = trace.getMemoryManager().getRegionsAddressSet(snap);
        var modules = new AddressSet();
        for (TraceModule m : trace.getModuleManager().getAllModules()) {
            var r = m.getRange(snap);
            if (r != null) modules.add(r);
        }
        var nonModule = new AddressSet(all);
        nonModule.delete(modules);
        var ordered = new ArrayList<AddressRange>();
        for (var r : nonModule) ordered.add(r);
        if (!excludeModules) {
            for (var r : modules) ordered.add(r);
        }
        return ordered;
    }

    private void runScan(ScanSession session, List<AddressRange> ranges, byte[] needle,
            ScanValues.Type type, boolean bigEndian, long budget, double tol) {
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
                    byte[] data;
                    try {
                        data = dbg.readMemory(base.add(off), want, TaskMonitor.DUMMY);
                    } catch (Exception e) {
                        off += want;
                        continue;
                    }
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
            byte[] data;
            try {
                data = dbg.readMemory(spanStart, spanLen, TaskMonitor.DUMMY);
            } catch (Exception e) {
                data = null;
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
        List<Address> hits = new ArrayList<>();
        Map<Address, Double> last = new HashMap<>();

        ScanSession(ScanValues.Type type, boolean bigEndian, double target) {
            this.type = type;
            this.bigEndian = bigEndian;
            this.target = target;
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
