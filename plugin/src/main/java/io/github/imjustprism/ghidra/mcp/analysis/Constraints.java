package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class Constraints {

    private Constraints() {}

    public static String extract(PluginContext ctx, String addr, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            Function func = Addresses.functionAtOrContaining(program, a);
            if (func == null) return "No function at or containing " + addr;
            return run(program, func, q);
        });
    }

    private static String run(Program program, Function func, Map<String, String> q) {
        var t = Responses.table(q, new String[]{"addr", "lhs", "op", "rhs", "cond", "target"}, 64);
        var listing = program.getListing();
        var end = func.getBody().getMaxAddress();
        var it = listing.getInstructions(func.getEntryPoint(), true);
        Instruction pending = null;
        int total = 0;
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins.getAddress().compareTo(end) > 0) break;
            String mn = ins.getMnemonicString().toUpperCase();
            if (mn.equals("CMP") || mn.equals("TEST") || mn.equals("SUB") && ins.getNumOperands() == 2) {
                pending = ins;
                continue;
            }
            if (pending != null && isCondBranch(mn)) {
                emit(t, pending, ins, mn);
                total++;
                pending = null;
                continue;
            }
            if (!isFlagStable(mn)) {
                pending = null;
            }
        }
        return t.total(total).build();
    }

    private static void emit(Responses.Table t, Instruction cmp, Instruction jcc, String jmn) {
        String lhs = operand(cmp, 0);
        String rhs = operand(cmp, 1);
        String op = mapCond(cmp.getMnemonicString().toUpperCase(), jmn);
        Address target = jcc.getNumOperands() > 0 ? addressOperand(jcc, 0) : null;
        t.row(Responses.addr(cmp.getAddress()), lhs, op, rhs, jmn, target == null ? "" : Responses.addr(target));
    }

    private static String operand(Instruction ins, int idx) {
        if (idx >= ins.getNumOperands()) return "";
        var objs = ins.getOpObjects(idx);
        if (objs != null && objs.length == 1 && objs[0] instanceof Scalar s) {
            long v = s.getUnsignedValue();
            if (v <= 0x7f) return Long.toString(v);
            return "0x" + Long.toHexString(v);
        }
        return ins.getDefaultOperandRepresentation(idx);
    }

    private static Address addressOperand(Instruction ins, int idx) {
        var refs = ins.getOperandReferences(idx);
        if (refs != null && refs.length > 0) return refs[0].getToAddress();
        return null;
    }

    private static boolean isCondBranch(String mn) {
        return switch (mn) {
            case "JE", "JZ", "JNE", "JNZ", "JL", "JNGE", "JLE", "JNG",
                 "JG", "JNLE", "JGE", "JNL", "JA", "JNBE", "JAE", "JNB",
                 "JB", "JNAE", "JBE", "JNA", "JS", "JNS", "JO", "JNO",
                 "JP", "JPE", "JNP", "JPO", "JCXZ", "JECXZ", "JRCXZ" -> true;
            default -> false;
        };
    }

    private static boolean isFlagStable(String mn) {
        return switch (mn) {
            case "MOV", "LEA", "NOP", "PUSH", "POP" -> true;
            default -> false;
        };
    }

    private static String mapCond(String cmp, String j) {
        boolean isTest = cmp.equals("TEST");
        return switch (j) {
            case "JE", "JZ" -> isTest ? "&==0" : "==";
            case "JNE", "JNZ" -> isTest ? "&!=0" : "!=";
            case "JL", "JNGE" -> "<(s)";
            case "JLE", "JNG" -> "<=(s)";
            case "JG", "JNLE" -> ">(s)";
            case "JGE", "JNL" -> ">=(s)";
            case "JB", "JNAE" -> "<(u)";
            case "JBE", "JNA" -> "<=(u)";
            case "JA", "JNBE" -> ">(u)";
            case "JAE", "JNB" -> ">=(u)";
            case "JS" -> "sign";
            case "JNS" -> "!sign";
            default -> j.toLowerCase();
        };
    }
}
