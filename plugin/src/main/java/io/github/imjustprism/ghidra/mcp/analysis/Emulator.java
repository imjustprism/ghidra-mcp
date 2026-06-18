package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.Bufs;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class Emulator {

    private static final long STACK_BASE = 0x7fff0000L;
    private static final long RET_MARKER = 0xBADC0DE0L;

    private Emulator() {}

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
            long entrySp = STACK_BASE - ptr;
            emu.writeRegister(emu.getStackPointerRegister(), entrySp);
            emu.writeRegister(emu.getPCRegister(), func.getEntryPoint().getOffset());
            emu.writeMemory(defaultSpace.getAddress(entrySp), encode(RET_MARKER, ptr, bigEndian));
            for (var rn : new String[]{"lr", "LR", "ra"}) {
                var r = program.getLanguage().getRegister(rn);
                if (r != null) {
                    emu.writeRegister(r, BigInteger.valueOf(RET_MARKER));
                    break;
                }
            }

            var params = func.getParameters();
            int placed = 0;
            for (int i = 0; i < args.length && i < params.length; i++) {
                var storage = params[i].getVariableStorage();
                if (storage == null || !storage.isValid()) continue;
                if (storage.isRegisterStorage() && storage.getRegister() != null) {
                    emu.writeRegister(storage.getRegister(), BigInteger.valueOf(args[i]));
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
                    && ret.getVariableStorage().getRegister() != null) {
                var rv = emu.readRegister(ret.getVariableStorage().getRegister());
                out.append("return ").append(ret.getVariableStorage().getRegister().getName())
                        .append("=0x").append(rv == null ? "?" : rv.toString(16)).append('\n');
            }
            if (captureAddr != null && !captureAddr.isBlank() && captureLen > 0) {
                if (captureLen > 0x200000) throw new IllegalArgumentException("capture_length too large (max 2097152)");
                if (!reason.equals("returned")) {
                    out.append("memory capture skipped (function did not return)\n");
                } else {
                    var a = program.getAddressFactory().getAddress(captureAddr.trim());
                    if (a == null) throw new IllegalArgumentException("invalid capture address");
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
                long v = hex ? Long.parseUnsignedLong(p.substring(2), 16) : Long.parseUnsignedLong(p);
                out[i] = neg ? -v : v;
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
