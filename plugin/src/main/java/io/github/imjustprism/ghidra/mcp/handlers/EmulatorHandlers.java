package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.Bufs;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

public final class EmulatorHandlers {

    private static final int MAX_SESSIONS = 8;
    private static final long TTL_MS = 30 * 60 * 1000;
    private static final long DEFAULT_STACK = 0x7fff0000L;
    private static final int MAX_STEPS = 10_000_000;
    private static final int MAX_READ = 0x200000;

    private final PluginContext ctx;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final AtomicInteger seq = new AtomicInteger();
    private final Object lifecycleLock = new Object();

    public EmulatorHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    public void register(RouteTable routes) {
        routes.postForm("/emu_start", p -> start(p.get("start"), p.get("stack")));
        routes.postForm("/emu_step", p -> step(p.get("emu_id"), parseLong(p.get("count"), 1)));
        routes.postForm("/emu_run_to", p -> runTo(p.get("emu_id"), p.get("stop"),
                parseLong(p.get("max_steps"), 100000)));
        routes.getQuery("/emu_registers", q -> registers(q.get("emu_id")));
        routes.postForm("/emu_set_register", p -> setRegister(p.get("emu_id"), p.get("register"), p.get("value")));
        routes.getQuery("/emu_read_memory", q -> readMemory(q.get("emu_id"), q.get("address"),
                parseLong(q.get("length"), 64)));
        routes.postForm("/emu_write_memory", p -> writeMemory(p.get("emu_id"), p.get("address"), p.get("hex")));
        routes.postForm("/emu_close", p -> closeSession(p.get("emu_id")));
    }

    public void close() {
        synchronized (lifecycleLock) {
            for (var s : sessions.values()) dispose(s);
            sessions.clear();
        }
    }

    private String start(String startStr, String stackStr) {
        if (startStr == null || startStr.isBlank()) throw new IllegalArgumentException("start is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var start = program.getAddressFactory().getAddress(startStr.trim());
        if (start == null) throw new IllegalArgumentException("invalid start address: " + startStr);
        long stack = stackStr == null || stackStr.isBlank() ? DEFAULT_STACK : parseBig(stackStr).longValue();

        synchronized (lifecycleLock) {
            evictExpired();
            while (sessions.size() >= MAX_SESSIONS) {
                var oldest = sessions.values().stream().min(Comparator.comparingLong(s -> s.lastAccess)).orElse(null);
                if (oldest == null) break;
                sessions.values().remove(oldest);
                dispose(oldest);
            }
            var emu = new EmulatorHelper(program);
            try {
                emu.writeRegister(emu.getStackPointerRegister(), stack);
                emu.writeRegister(emu.getPCRegister(), start.getOffset());
            } catch (RuntimeException e) {
                emu.dispose();
                throw new IllegalStateException("failed to initialize emulator: " + e.getMessage(), e);
            }
            var id = "emu" + seq.incrementAndGet();
            sessions.put(id, new Session(emu, program));
            return "emu_id=" + id + "\nPC=" + emu.getExecutionAddress() + "\nSP=0x" + Long.toHexString(stack);
        }
    }

    private String step(String id, long count) {
        int n = (int) Math.min(Math.max(count, 1L), 100000L);
        return withSession(id, session -> {
            var emu = session.emu;
            int done = 0;
            String reason = "ok";
            for (; done < n; done++) {
                try {
                    if (!emu.step(TaskMonitor.DUMMY)) {
                        reason = "halt: " + emu.getLastError();
                        break;
                    }
                } catch (Exception e) {
                    reason = "error: " + e.getMessage();
                    break;
                }
            }
            return "stepped=" + done + " (" + reason + ")\nPC=" + emu.getExecutionAddress();
        });
    }

    private String runTo(String id, String stopStr, long maxSteps) {
        if (stopStr == null || stopStr.isBlank()) throw new IllegalArgumentException("stop is required");
        int limit = (int) Math.min(Math.max(maxSteps, 1L), MAX_STEPS);
        return withSession(id, session -> {
            var emu = session.emu;
            var stop = addr(session.program, stopStr);
            int steps = 0;
            String reason = "max_steps";
            for (; steps < limit; steps++) {
                var pc = emu.getExecutionAddress();
                if (pc == null) { reason = "no execution address"; break; }
                if (pc.equals(stop)) { reason = "hit stop"; break; }
                try {
                    if (!emu.step(TaskMonitor.DUMMY)) { reason = "halt: " + emu.getLastError(); break; }
                } catch (Exception e) {
                    reason = "error: " + e.getMessage();
                    break;
                }
            }
            return "steps=" + steps + " (" + reason + ")\nPC=" + emu.getExecutionAddress();
        });
    }

    private String registers(String id) {
        return withSession(id, session -> {
            var t = Responses.table(Map.of(), new String[]{"register", "value"}, 32);
            for (var reg : session.program.getLanguage().getRegisters()) {
                if (!reg.isBaseRegister() || reg.isProcessorContext()) continue;
                try {
                    var v = session.emu.readRegister(reg);
                    if (v != null) t.row(reg.getName(), "0x" + v.toString(16));
                } catch (RuntimeException e) {
                    Msg.trace(EmulatorHandlers.class, "read register " + reg.getName(), e);
                }
            }
            return t.build();
        });
    }

    private String setRegister(String id, String register, String value) {
        if (register == null || register.isBlank()) throw new IllegalArgumentException("register is required");
        if (value == null || value.isBlank()) throw new IllegalArgumentException("value is required");
        var big = parseBig(value);
        return withSession(id, session -> {
            if (session.program.getRegister(register.trim()) == null) {
                throw new IllegalArgumentException("unknown register: " + register);
            }
            session.emu.writeRegister(register.trim(), big);
            return "set " + register.trim() + "=0x" + big.toString(16);
        });
    }

    private String readMemory(String id, String addrStr, long length) {
        int len = (int) Math.min(Math.max(length, 1L), MAX_READ);
        return withSession(id, session -> {
            var a = addr(session.program, addrStr);
            var data = session.emu.readMemory(a, len);
            if (data == null) throw new IllegalStateException("emulator memory unavailable at " + Responses.addr(a));
            return Responses.addr(a) + "\t" + data.length + "\t" + Bufs.hex(data);
        });
    }

    private String writeMemory(String id, String addrStr, String hex) {
        if (hex == null || hex.isBlank()) throw new IllegalArgumentException("hex is required");
        var bytes = Bufs.parseHex(hex);
        return withSession(id, session -> {
            var a = addr(session.program, addrStr);
            session.emu.writeMemory(a, bytes);
            return "wrote " + bytes.length + " bytes to " + Responses.addr(a);
        });
    }

    private String closeSession(String id) {
        if (id == null || id.isBlank()) throw new IllegalArgumentException("emu_id is required");
        var session = sessions.remove(id);
        if (session == null) return "unknown emu_id: " + id;
        dispose(session);
        return "closed " + id + " (" + sessions.size() + " session(s) remain)";
    }

    private <T> T withSession(String id, Function<Session, T> body) {
        if (id == null || id.isBlank()) throw new IllegalArgumentException("emu_id is required");
        evictExpired();
        var session = sessions.get(id);
        if (session == null) throw new IllegalArgumentException("unknown emu_id (run emu_start first): " + id);
        session.lock.lock();
        try {
            if (session.disposed) {
                throw new IllegalArgumentException("emu_id no longer active (closed or expired): " + id);
            }
            session.touch();
            return body.apply(session);
        } finally {
            session.lock.unlock();
        }
    }

    private Address addr(Program program, String s) {
        if (s == null || s.isBlank()) throw new IllegalArgumentException("address is required");
        var a = program.getAddressFactory().getAddress(s.trim());
        if (a == null) throw new IllegalArgumentException("invalid address: " + s);
        return a;
    }

    private void evictExpired() {
        long now = System.currentTimeMillis();
        var expired = new ArrayList<Map.Entry<String, Session>>();
        for (var e : sessions.entrySet()) {
            if (now - e.getValue().lastAccess > TTL_MS) expired.add(e);
        }
        for (var e : expired) {
            if (sessions.remove(e.getKey(), e.getValue())) dispose(e.getValue());
        }
    }

    private void dispose(Session s) {
        s.lock.lock();
        try {
            if (!s.disposed) {
                s.disposed = true;
                s.emu.dispose();
            }
        } finally {
            s.lock.unlock();
        }
    }

    private static long parseLong(String s, long d) {
        if (s == null || s.isBlank()) return d;
        try {
            return Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return d;
        }
    }

    private static BigInteger parseBig(String s) {
        var v = s.trim();
        boolean neg = v.startsWith("-");
        if (neg) v = v.substring(1).trim();
        boolean hex = v.startsWith("0x") || v.startsWith("0X");
        var mag = hex ? new BigInteger(v.substring(2), 16) : new BigInteger(v);
        return neg ? mag.negate() : mag;
    }

    private static final class Session {
        final EmulatorHelper emu;
        final Program program;
        final ReentrantLock lock = new ReentrantLock();
        volatile boolean disposed = false;
        volatile long lastAccess = System.currentTimeMillis();

        Session(EmulatorHelper emu, Program program) {
            this.emu = emu;
            this.program = program;
        }

        void touch() {
            lastAccess = System.currentTimeMillis();
        }
    }
}
