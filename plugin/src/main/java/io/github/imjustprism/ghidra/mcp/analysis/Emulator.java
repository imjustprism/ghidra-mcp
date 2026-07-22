package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.Bufs;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public final class Emulator {

    private static final long STACK_BASE = 0x7fff0000L;
    private static final long RET_MARKER = 0xBADC0DE0L;
    private static final int SCAN_CHUNK = 8192;
    private static final int MAX_OUTPUT_SCAN = 0x100000;

    private Emulator() {}

    public record DecodedString(String kind, String encoding, long address, String text) {}

    public static String recoverDecodedStrings(PluginContext ctx, String funcAddr, String argsCsv,
                                               int minLen, int maxSteps, String outAddr, int outLen,
                                               Map<String, String> q) {
        if (funcAddr == null || funcAddr.isBlank()) throw new IllegalArgumentException("function_address required");
        if (maxSteps <= 0 || maxSteps > 10_000_000) throw new IllegalArgumentException("max_steps must be 1..10000000");
        int min = Math.min(Math.max(minLen, 1), 256);
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var entry = program.getAddressFactory().getAddress(funcAddr.trim());
        if (entry == null) throw new IllegalArgumentException("invalid function_address: " + funcAddr);
        var func = Addresses.functionAtOrContaining(program, entry);
        if (func == null) throw new IllegalArgumentException("no function at " + funcAddr);
        var defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
        if (!func.getEntryPoint().getAddressSpace().equals(defaultSpace)) {
            throw new IllegalArgumentException("function must be in the default address space");
        }
        long[] args = parseArgs(argsCsv);
        boolean bigEndian = program.getLanguage().isBigEndian();
        int ptr = defaultSpace.getPointerSize();

        var emu = new ghidra.app.emulator.EmulatorHelper(program);
        try {
            prepareCall(emu, program, func, args, bigEndian, ptr);
            emu.enableMemoryWriteTracking(true);
            int steps = 0;
            String reason = "max_steps";
            for (; steps < maxSteps; steps++) {
                var pc = emu.getExecutionAddress();
                if (pc == null) { reason = "no execution address"; break; }
                if (pc.getOffset() == RET_MARKER && pc.getAddressSpace().equals(defaultSpace)) {
                    reason = "returned";
                    break;
                }
                try {
                    if (!emu.step(ghidra.util.task.TaskMonitor.DUMMY)) { reason = "halt: " + emu.getLastError(); break; }
                } catch (Exception e) {
                    reason = "error: " + e.getMessage();
                    break;
                }
            }

            var seen = new LinkedHashSet<String>();
            var rows = new ArrayList<DecodedString>();

            var written = emu.getTrackedMemoryWriteSet();
            long scanned = 0;
            if (written != null) {
                for (var range : written) {
                    if (!range.getMinAddress().getAddressSpace().equals(defaultSpace)) continue;
                    if (scanned >= MAX_OUTPUT_SCAN) break;
                    int take = (int) Math.min(range.getLength(), MAX_OUTPUT_SCAN - scanned);
                    scanRegion(emu, defaultSpace, range.getMinAddress().getOffset(), take, "write", min, seen, rows);
                    scanned += take;
                }
            }
            if (outAddr != null && !outAddr.isBlank() && outLen > 0) {
                var a = program.getAddressFactory().getAddress(outAddr.trim());
                if (a == null || !a.getAddressSpace().equals(defaultSpace)) {
                    throw new IllegalArgumentException("invalid output_addr (must be in default address space)");
                }
                scanRegion(emu, defaultSpace, a.getOffset(), Math.min(outLen, MAX_OUTPUT_SCAN), "output", min, seen, rows);
            }

            var t = Responses.table(q, new String[]{"kind", "encoding", "address", "string"}, rows.size());
            for (var r : rows) t.row(r.kind(), r.encoding(), "0x" + Long.toHexString(r.address()), r.text());
            return "# recover_decoded_strings " + func.getName() + " — " + steps + " steps (" + reason
                    + "), " + rows.size() + " string(s) min_len=" + min + "\n" + t.total(rows.size()).build();
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            Msg.error(ctx.logOwner(), "recover_decoded_strings failed", e);
            return "recover_decoded_strings error: " + e.getMessage();
        } finally {
            emu.dispose();
        }
    }

    private static final long[][] FINGERPRINT_VECTORS = {
        {1, 2, 3, 4}, {0, 0, 0, 0}, {-1, -1, -1, -1},
        {0x1111_1111L, 0x2222_2222L, 0x3333_3333L, 0x4444_4444L},
        {0xdead_beefL, 0xcafe_f00dL, 5, 7}, {7, 11, 13, 17},
    };

    public static String semanticFingerprint(PluginContext ctx, String funcAddr, Map<String, String> q) {
        if (funcAddr == null || funcAddr.isBlank()) throw new IllegalArgumentException("function_address required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var entry = program.getAddressFactory().getAddress(funcAddr.trim());
        if (entry == null) throw new IllegalArgumentException("invalid function_address: " + funcAddr);
        var func = Addresses.functionAtOrContaining(program, entry);
        if (func == null) throw new IllegalArgumentException("no function at " + funcAddr);
        var defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
        if (!func.getEntryPoint().getAddressSpace().equals(defaultSpace)) {
            throw new IllegalArgumentException("function must be in the default address space");
        }
        boolean bigEndian = program.getLanguage().isBigEndian();
        int ptr = defaultSpace.getPointerSize();
        long hash = 0xcbf29ce484222325L;
        var t = Responses.table(q, new String[]{"vector", "ret", "write_bytes", "steps", "halt"}, FINGERPRINT_VECTORS.length);
        for (var vec : FINGERPRINT_VECTORS) {
            var bh = behavior(program, func, vec, bigEndian, ptr, defaultSpace);
            var line = vecStr(vec) + "|" + bh.ret() + "|" + bh.writeBytes() + "|" + bh.reason();
            for (int i = 0; i < line.length(); i++) {
                hash = (hash ^ line.charAt(i)) * 0x100000001b3L;
            }
            t.row(vecStr(vec), "0x" + Long.toHexString(bh.ret()), bh.writeBytes(), bh.steps(), bh.reason());
        }
        return "# semantic fingerprint " + func.getName() + ": 0x" + Long.toHexString(hash)
                + " (behavioral — emulated over " + FINGERPRINT_VECTORS.length
                + " input vectors; robust to instruction substitution / recompilation)\n" + t.build();
    }

    public static String semanticDiff(PluginContext ctx, String addrA, String addrB, Map<String, String> q) {
        if (addrA == null || addrA.isBlank() || addrB == null || addrB.isBlank()) {
            throw new IllegalArgumentException("address_a and address_b are required");
        }
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var defaultSpace = program.getAddressFactory().getDefaultAddressSpace();

        var aAddr = Addresses.resolve(program, addrA);
        var bAddr = Addresses.resolve(program, addrB);
        if (aAddr == null) throw new IllegalArgumentException("invalid address_a: " + addrA);
        if (bAddr == null) throw new IllegalArgumentException("invalid address_b: " + addrB);
        var funcA = Addresses.functionAtOrContaining(program, aAddr);
        var funcB = Addresses.functionAtOrContaining(program, bAddr);
        if (funcA == null || funcB == null) {
            throw new IllegalArgumentException("no function at address_a or address_b"
                    + " (resolved a=" + Responses.addr(aAddr) + " b=" + Responses.addr(bAddr) + ")");
        }
        boolean bigEndian = program.getLanguage().isBigEndian();
        int ptr = defaultSpace.getPointerSize();
        int match = 0;
        var t = Responses.table(q, new String[]{"vector", "a_ret", "b_ret", "a_wbytes", "b_wbytes", "same"},
                FINGERPRINT_VECTORS.length);
        for (var vec : FINGERPRINT_VECTORS) {
            var a = behavior(program, funcA, vec, bigEndian, ptr, defaultSpace);
            var b = behavior(program, funcB, vec, bigEndian, ptr, defaultSpace);
            boolean same = a.ret() == b.ret() && a.writeBytes() == b.writeBytes() && a.reason().equals(b.reason());
            if (same) match++;
            t.row(vecStr(vec), "0x" + Long.toHexString(a.ret()), "0x" + Long.toHexString(b.ret()),
                    a.writeBytes(), b.writeBytes(), same);
        }
        int score = match * 100 / FINGERPRINT_VECTORS.length;
        return "# semantic diff " + funcA.getName() + " vs " + funcB.getName() + ": " + score
                + "/100 (" + match + "/" + FINGERPRINT_VECTORS.length
                + " input vectors produce identical observable behavior; matches across instruction substitution)\n"
                + t.build();
    }

    private record Behavior(long ret, long writeBytes, String reason, int steps) {}

    private static Behavior behavior(ghidra.program.model.listing.Program program,
                                     ghidra.program.model.listing.Function func, long[] vec,
                                     boolean bigEndian, int ptr,
                                     ghidra.program.model.address.AddressSpace defaultSpace) {
        var emu = new ghidra.app.emulator.EmulatorHelper(program);
        try {
            prepareCall(emu, program, func, vec, bigEndian, ptr);
            emu.enableMemoryWriteTracking(true);
            String reason = "max_steps";
            int steps = 0;
            for (; steps < 50_000; steps++) {
                var pc = emu.getExecutionAddress();
                if (pc == null) { reason = "no-pc"; break; }
                if (pc.getOffset() == RET_MARKER && pc.getAddressSpace().equals(defaultSpace)) { reason = "ret"; break; }
                try {
                    if (!emu.step(ghidra.util.task.TaskMonitor.DUMMY)) { reason = "halt"; break; }
                } catch (Exception e) {
                    reason = "fault";
                    break;
                }
            }
            long ret = reason.equals("ret") ? returnValue(emu, func) : 0;
            return new Behavior(ret, trackedBytes(emu, defaultSpace), reason, steps);
        } finally {
            emu.dispose();
        }
    }

    private static long returnValue(ghidra.app.emulator.EmulatorHelper emu, ghidra.program.model.listing.Function func) {
        var ret = func.getReturn();
        if (ret == null || ret.getVariableStorage() == null || !ret.getVariableStorage().isRegisterStorage()
                || ret.getVariableStorage().getRegister() == null) {
            return 0;
        }
        var v = emu.readRegister(ret.getVariableStorage().getRegister());
        return v == null ? 0 : v.longValue();
    }

    private static long trackedBytes(ghidra.app.emulator.EmulatorHelper emu,
                                     ghidra.program.model.address.AddressSpace defaultSpace) {
        var ws = emu.getTrackedMemoryWriteSet();
        if (ws == null) return 0;
        long n = 0;
        for (var r : ws) {
            if (r.getMinAddress().getAddressSpace().equals(defaultSpace)) n += r.getLength();
        }
        return n;
    }

    private static String vecStr(long[] vec) {
        var sb = new StringBuilder();
        for (int i = 0; i < vec.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(Long.toHexString(vec[i]));
        }
        return sb.toString();
    }

    private static long prepareCall(ghidra.app.emulator.EmulatorHelper emu, ghidra.program.model.listing.Program program,
                                    ghidra.program.model.listing.Function func, long[] args, boolean bigEndian, int ptr) {
        var defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
        ghidra.program.model.lang.Register lrReg = null;
        for (var rn : new String[]{"lr", "LR", "ra"}) {
            var r = program.getLanguage().getRegister(rn);
            if (r != null) { lrReg = r; break; }
        }
        long entrySp;
        if (lrReg != null) {
            entrySp = STACK_BASE;
            emu.writeRegister(emu.getStackPointerRegister(), entrySp);
            emu.writeRegister(lrReg, unsigned64(RET_MARKER));
        } else {
            entrySp = STACK_BASE - ptr;
            emu.writeRegister(emu.getStackPointerRegister(), entrySp);
            emu.writeMemory(defaultSpace.getAddress(entrySp), encode(RET_MARKER, ptr, bigEndian));
        }
        emu.writeRegister(emu.getPCRegister(), func.getEntryPoint().getOffset());
        var params = func.getParameters();
        for (int i = 0; i < args.length && i < params.length; i++) {
            var storage = params[i].getVariableStorage();
            if (storage == null || !storage.isValid()) continue;
            if (storage.isRegisterStorage() && storage.getRegisters().size() == 1 && storage.getRegister() != null) {
                emu.writeRegister(storage.getRegister(), unsigned64(args[i]));
            } else if (storage.isStackStorage()) {
                long at = entrySp + storage.getStackOffset();
                int sz = Math.min(Math.max(storage.size(), 1), 8);
                emu.writeMemory(defaultSpace.getAddress(at), encode(args[i], sz, bigEndian));
            }
        }
        return entrySp;
    }

    private static void scanRegion(ghidra.app.emulator.EmulatorHelper emu,
                                   ghidra.program.model.address.AddressSpace space, long base, int len,
                                   String kind, int minLen, LinkedHashSet<String> seen, List<DecodedString> out) {
        for (int off = 0; off < len; off += SCAN_CHUNK) {
            int n = Math.min(SCAN_CHUNK, len - off);
            byte[] data;
            try {
                data = emu.readMemory(space.getAddress(base + off), n);
            } catch (RuntimeException e) {
                continue;
            }
            if (data == null) continue;
            for (var f : extractStrings(data, minLen)) {
                if (seen.add(f.encoding() + ':' + f.text())) {
                    out.add(new DecodedString(kind, f.encoding(), base + off + f.offset(), f.text()));
                }
            }
        }
    }

    public record Found(String encoding, int offset, String text) {}

    public static List<Found> extractStrings(byte[] b, int minLen) {
        var out = new ArrayList<Found>();
        int i = 0;
        while (i < b.length) {
            if (isPrintable(b[i])) {
                int j = i;
                while (j < b.length && isPrintable(b[j])) j++;
                if (j - i >= minLen) out.add(new Found("ascii", i, new String(b, i, j - i, StandardCharsets.US_ASCII)));
                i = j;
            } else {
                i++;
            }
        }
        i = 0;
        while (i + 1 < b.length) {
            if (isPrintable(b[i]) && b[i + 1] == 0) {
                int j = i;
                var sb = new StringBuilder();
                while (j + 1 < b.length && isPrintable(b[j]) && b[j + 1] == 0) {
                    sb.append((char) (b[j] & 0xff));
                    j += 2;
                }
                if (sb.length() >= minLen) out.add(new Found("utf16le", i, sb.toString()));
                i = j;
            } else {
                i++;
            }
        }
        return out;
    }

    private static boolean isPrintable(byte c) {
        int v = c & 0xff;
        return v >= 0x20 && v < 0x7f;
    }

    public static String emulateFunction(PluginContext ctx, String funcAddr, String argsCsv,
                                         int maxSteps, String captureAddr, int captureLen) {
        if (funcAddr == null || funcAddr.isBlank()) throw new IllegalArgumentException("function_address required");
        if (maxSteps <= 0 || maxSteps > 10_000_000) throw new IllegalArgumentException("max_steps must be 1..10000000");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var entry = program.getAddressFactory().getAddress(funcAddr.trim());
        if (entry == null) throw new IllegalArgumentException("invalid function_address: " + funcAddr);
        var func = Addresses.functionAtOrContaining(program, entry);
        if (func == null) throw new IllegalArgumentException("no function at " + funcAddr);
        var defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
        if (!func.getEntryPoint().getAddressSpace().equals(defaultSpace)) {
            throw new IllegalArgumentException("function must be in the default address space");
        }
        long[] args = parseArgs(argsCsv);
        boolean bigEndian = program.getLanguage().isBigEndian();

        var emu = new ghidra.app.emulator.EmulatorHelper(program);
        var out = new StringBuilder();
        try {
            int ptr = defaultSpace.getPointerSize();
            ghidra.program.model.lang.Register lrReg = null;
            for (var rn : new String[]{"lr", "LR", "ra"}) {
                var r = program.getLanguage().getRegister(rn);
                if (r != null) {
                    lrReg = r;
                    break;
                }
            }

            long entrySp;
            if (lrReg != null) {
                entrySp = STACK_BASE;
                emu.writeRegister(emu.getStackPointerRegister(), entrySp);
                emu.writeRegister(lrReg, unsigned64(RET_MARKER));
            } else {
                entrySp = STACK_BASE - ptr;
                emu.writeRegister(emu.getStackPointerRegister(), entrySp);
                emu.writeMemory(defaultSpace.getAddress(entrySp), encode(RET_MARKER, ptr, bigEndian));
            }
            emu.writeRegister(emu.getPCRegister(), func.getEntryPoint().getOffset());

            var params = func.getParameters();
            int placed = 0;
            for (int i = 0; i < args.length && i < params.length; i++) {
                var storage = params[i].getVariableStorage();
                if (storage == null || !storage.isValid()) continue;
                if (storage.isRegisterStorage() && storage.getRegisters().size() == 1
                        && storage.getRegister() != null) {
                    emu.writeRegister(storage.getRegister(), unsigned64(args[i]));
                    placed++;
                } else if (storage.isStackStorage()) {
                    long at = entrySp + storage.getStackOffset();
                    int sz = Math.min(Math.max(storage.size(), 1), 8);
                    emu.writeMemory(defaultSpace.getAddress(at), encode(args[i], sz, bigEndian));
                    placed++;
                }
            }

            var pcReg = emu.getPCRegister();
            int steps = 0;
            String reason = "max_steps";
            for (; steps < maxSteps; steps++) {
                var pc = emu.getExecutionAddress();
                if (pc == null) { reason = "no execution address"; break; }
                if (pc.getOffset() == RET_MARKER && pc.getAddressSpace().equals(defaultSpace)) {
                    reason = "returned";
                    break;
                }
                try {
                    if (!emu.step(ghidra.util.task.TaskMonitor.DUMMY)) {
                        reason = "halt: " + emu.getLastError();
                        break;
                    }
                } catch (Exception e) {
                    reason = "error: " + e.getMessage();
                    break;
                }
            }

            out.append("function=").append(func.getName()).append(" args_placed=").append(placed)
                    .append('/').append(args.length).append('\n');
            out.append("stopped after ").append(steps).append(" steps (").append(reason).append(")\n");
            var ret = func.getReturn();
            if (!reason.equals("returned")) {
                out.append("return value not reported (function did not return)\n");
            } else if (ret != null && ret.getVariableStorage() != null
                    && ret.getVariableStorage().isRegisterStorage()
                    && ret.getVariableStorage().getRegisters().size() == 1
                    && ret.getVariableStorage().getRegister() != null) {
                var rv = emu.readRegister(ret.getVariableStorage().getRegister());
                out.append("return ").append(ret.getVariableStorage().getRegister().getName())
                        .append("=0x").append(rv == null ? "?" : rv.toString(16)).append('\n');
            } else if (ret != null && ret.getVariableStorage() != null
                    && ret.getVariableStorage().isRegisterStorage()) {
                out.append("return value in compound register storage (not reported)\n");
            }
            if (captureAddr != null && !captureAddr.isBlank() && captureLen > 0) {
                if (captureLen > 0x200000) throw new IllegalArgumentException("capture_length too large (max 2097152)");
                if (!reason.equals("returned")) {
                    out.append("memory capture skipped (function did not return)\n");
                } else {
                    var a = program.getAddressFactory().getAddress(captureAddr.trim());
                    if (a == null) throw new IllegalArgumentException("invalid capture address");
                    if (!a.getAddressSpace().equals(defaultSpace)) {
                        throw new IllegalArgumentException("capture address must be in the default address space");
                    }
                    var data = emu.readMemory(a, captureLen);
                    out.append("captured ").append(Responses.addr(a)).append(": ")
                            .append(data == null ? "unavailable" : Bufs.hex(data)).append('\n');
                }
            }
            return out.toString();
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            Msg.error(ctx.logOwner(), "emulate_function failed", e);
            return out + "emulate_function error: " + e.getMessage();
        } finally {
            emu.dispose();
        }
    }

    private static BigInteger unsigned64(long v) {
        var b = BigInteger.valueOf(v);
        return b.signum() < 0 ? b.add(BigInteger.ONE.shiftLeft(64)) : b;
    }

    private static long[] parseArgs(String csv) {
        if (csv == null || csv.isBlank()) return new long[0];
        var parts = csv.split(",");
        var out = new long[parts.length];
        for (int i = 0; i < parts.length; i++) {
            var p = parts[i].trim();
            if (p.isEmpty()) throw new IllegalArgumentException("empty argument at position " + i);
            boolean neg = p.startsWith("-");
            if (neg) p = p.substring(1).trim();
            boolean hex = p.startsWith("0x") || p.startsWith("0X");
            try {
                long mag = hex ? Long.parseUnsignedLong(p.substring(2), 16) : Long.parseUnsignedLong(p);
                if (neg) {
                    if (Long.compareUnsigned(mag, 0x8000000000000000L) > 0) {
                        throw new IllegalArgumentException("negative argument out of 64-bit range at position " + i);
                    }
                    out[i] = -mag;
                } else {
                    out[i] = mag;
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("invalid argument at position " + i + ": " + parts[i].trim());
            }
        }
        return out;
    }

    private static byte[] encode(long value, int size, boolean bigEndian) {
        var buf = ByteBuffer.allocate(8).order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        buf.putLong(value);
        var full = buf.array();
        var out = new byte[size];
        if (bigEndian) {
            System.arraycopy(full, 8 - size, out, 0, size);
        } else {
            System.arraycopy(full, 0, out, 0, size);
        }
        return out;
    }

    public static String emulate(PluginContext ctx,
                                 String startAddr, String stopAddr, int maxSteps,
                                 String skipCsv, String captureAddr, int captureLen, boolean commit) {
        if (startAddr == null || startAddr.isEmpty()) throw new IllegalArgumentException("start address required");
        if (maxSteps <= 0 || maxSteps > 10_000_000) throw new IllegalArgumentException("max_steps must be 1..10000000");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");

        var skip = new java.util.HashSet<Long>();
        if (!skipCsv.isEmpty()) {
            for (var tok : skipCsv.split(",")) {
                try { skip.add(Long.decode(tok.trim())); }
                catch (NumberFormatException e) { Msg.trace(Emulator.class, "skip-csv parse", e); }
            }
        }

        var emu = new ghidra.app.emulator.EmulatorHelper(program);
        var result = new StringBuilder();
        try {
            var start = program.getAddressFactory().getAddress(startAddr);
            if (start == null) throw new IllegalArgumentException("Invalid start address");
            var stop = stopAddr == null || stopAddr.isEmpty()
                    ? null : program.getAddressFactory().getAddress(stopAddr);

            long stackBase = 0x7fff0000L;
            emu.writeRegister(emu.getStackPointerRegister(), stackBase);
            emu.writeRegister(emu.getPCRegister(), start.getOffset());

            var pcReg = emu.getPCRegister();
            int steps = 0;
            String stopReason = "max_steps";
            for (; steps < maxSteps; steps++) {
                var pcAddr = emu.getExecutionAddress();
                if (pcAddr == null) { stopReason = "no execution address"; break; }
                if (stop != null && pcAddr.equals(stop)) { stopReason = "hit stop"; break; }

                if (skip.contains(pcAddr.getOffset())) {
                    var ins = program.getListing().getInstructionAt(pcAddr);
                    if (ins != null) {
                        var next = pcAddr.add(ins.getLength());
                        emu.writeRegister(pcReg, next.getOffset());
                        continue;
                    }
                }

                var ins = program.getListing().getInstructionAt(pcAddr);
                if (ins != null) {
                    var mnem = ins.getMnemonicString();
                    if ((mnem.equalsIgnoreCase("CALL") || mnem.equalsIgnoreCase("JMP"))
                            && ins.getNumOperands() == 1) {
                        var ref = ins.getReferencesFrom();
                        for (var r : ref) {
                            if (r.getReferenceType().isCall()
                                    && skip.contains(r.getToAddress().getOffset())) {
                                var next = pcAddr.add(ins.getLength());
                                emu.writeRegister(pcReg, next.getOffset());
                                ins = null;
                                break;
                            }
                        }
                        if (ins == null) continue;
                    }
                }

                if (!emu.step(ghidra.util.task.TaskMonitor.DUMMY)) {
                    stopReason = "emulator halt: " + emu.getLastError();
                    break;
                }
            }

            result.append("Stopped after ").append(steps).append(" steps (").append(stopReason).append(")\n");
            var finalPc = emu.getExecutionAddress();
            if (finalPc != null) result.append("Final PC: ").append(finalPc).append('\n');

            if (!captureAddr.isEmpty() && captureLen > 0) {
                if (captureLen > 0x200000) return result + "\ncapture_length too large (max 2097152)";
                var a = program.getAddressFactory().getAddress(captureAddr);
                var data = emu.readMemory(a, captureLen);
                if (data == null) return result + "\ncaptured memory unavailable";
                if (commit) {
                    var block = program.getMemory().getBlock(a);
                    if (block != null) {
                        boolean wasWrite = block.isWrite();
                        if (!wasWrite) block.setWrite(true);
                        var tx = program.startTransaction("Commit emulator memory");
                        boolean ok = false;
                        try {
                            program.getListing().clearCodeUnits(a, a.add(captureLen - 1), false);
                            program.getMemory().setBytes(a, data);
                            ok = true;
                        } finally {
                            program.endTransaction(tx, ok);
                            if (!wasWrite) block.setWrite(false);
                        }
                        result.append("Committed ").append(captureLen).append(" bytes to ").append(a).append('\n');
                    } else {
                        result.append("No block at capture address, returning hex instead\n");
                    }
                }
                var sb = new StringBuilder();
                int preview = Math.min(data.length, 512);
                for (int i = 0; i < preview; i++) sb.append("%02x".formatted(data[i] & 0xFF));
                result.append("First ").append(preview).append(" bytes: ").append(sb);
                if (data.length > preview) result.append("... (").append(data.length).append(" total)");
            }
            return result.toString();
        } catch (Exception e) {
            Msg.error(ctx.logOwner(), "emulate failed", e);
            return result + "\nemulate error";
        } finally {
            emu.dispose();
        }
    }
}
