package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class MagicConstants {

    private MagicConstants() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        long min = parseLong(q.get("min"), 0x100L);
        long max = parseLong(q.get("max"), 0xffffffffL);
        return ctx.withProgram(program -> run(program, min, max, p, q));
    }

    private static String run(Program program, long min, long max, Page p, Map<String, String> q) {
        var t = Responses.table(p, q, new String[]{"addr", "func", "instr", "value", "dec"});
        var w = new Responses.Window(p);
        var listing = program.getListing();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!block.isExecute()) continue;
            Address cur = block.getStart();
            Address end = block.getEnd();
            var it = listing.getInstructions(cur, true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                if (ins.getAddress().compareTo(end) > 0) break;
                String mn = ins.getMnemonicString().toUpperCase();
                if (!isInteresting(mn)) continue;
                for (int i = 0; i < ins.getNumOperands(); i++) {
                    var objs = ins.getOpObjects(i);
                    if (objs == null) continue;
                    for (var o : objs) {
                        if (!(o instanceof Scalar s)) continue;
                        long v = s.getUnsignedValue();
                        if (v < min || v > max) continue;
                        if (isUninteresting(v)) continue;
                        if (!w.take()) continue;
                        Function f = program.getFunctionManager().getFunctionContaining(ins.getAddress());
                        String fname = f == null ? "" : f.getName();
                        t.row(Responses.addr(ins.getAddress()), fname, ins.toString(),
                              "0x" + Long.toHexString(v), v);
                    }
                }
            }
        }
        return t.total(w.total()).build();
    }

    private static boolean isInteresting(String mn) {
        return switch (mn) {
            case "CMP", "MOV", "ADD", "SUB", "XOR", "AND", "OR",
                 "IMUL", "MUL", "TEST", "LEA", "SHL", "SHR", "SAR",
                 "ROL", "ROR", "PUSH" -> true;
            default -> false;
        };
    }

    private static boolean isUninteresting(long v) {
        if (v == 0 || v == 1 || v == 2 || v == 3 || v == 4 || v == 8
                || v == 16 || v == 32 || v == 64 || v == 128 || v == 256) return true;
        if (v == 0xff || v == 0xffff || v == 0xffffff || v == 0xffffffffL) return true;
        return false;
    }

    private static long parseLong(String s, long def) {
        if (s == null || s.isEmpty()) return def;
        try {
            String t = s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s;
            int radix = s.startsWith("0x") || s.startsWith("0X") ? 16 : 10;
            return Long.parseLong(t, radix);
        } catch (NumberFormatException e) {
            Msg.trace(MagicConstants.class, "min/max parse", e);
            return def;
        }
    }
}
