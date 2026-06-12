package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;

public final class Emulator {

    private Emulator() {}

    public static String emulate(PluginContext ctx,
                                 String startAddr, String stopAddr, int maxSteps,
                                 String skipCsv, String captureAddr, int captureLen, boolean commit) {
        if (startAddr == null || startAddr.isEmpty()) throw new IllegalArgumentException("start address required");
        if (maxSteps <= 0 || maxSteps > 10_000_000) throw new IllegalArgumentException("max_steps must be 1..10000000");
        var program = ctx.currentProgram();
        if (program == null) return "No program loaded";

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
            if (start == null) return "Invalid start address";
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
