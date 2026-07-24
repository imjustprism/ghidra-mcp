package io.github.imjustprism.ghidra.mcp.analysis.mba;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class MbaExtract {

    public record Extracted(MbaExpr expr, int nvars, List<String> leaves) {}

    private MbaExtract() {}

    public static Extracted fromVarnode(Varnode out) {
        var leaves = new LinkedHashMap<String, Integer>();
        var expr = build(out, leaves, 0);
        if (expr == null) return null;
        return new Extracted(expr, leaves.size(), new ArrayList<>(leaves.keySet()));
    }

    public static MbaExpr build(Varnode vn, Map<String, Integer> leaves) {
        return build(vn, leaves, 0);
    }

    private static MbaExpr build(Varnode vn, Map<String, Integer> leaves, int depth) {
        if (vn == null || depth > 64) return null;
        if (vn.isConstant()) return new MbaExpr.Const(vn.getOffset());
        var def = vn.getDef();
        if (def != null) {
            var op = def.getOpcode();
            switch (op) {
                case PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT ->
                        { return build(def.getInput(0), leaves, depth + 1); }
                case PcodeOp.INT_ADD -> { return bin(MbaExpr.Add::new, def, leaves, depth); }
                case PcodeOp.INT_SUB -> { return bin(MbaExpr.Sub::new, def, leaves, depth); }
                case PcodeOp.INT_MULT -> { return bin(MbaExpr.Mul::new, def, leaves, depth); }
                case PcodeOp.INT_AND -> { return bin(MbaExpr.And::new, def, leaves, depth); }
                case PcodeOp.INT_OR -> { return bin(MbaExpr.Or::new, def, leaves, depth); }
                case PcodeOp.INT_XOR -> { return bin(MbaExpr.Xor::new, def, leaves, depth); }
                case PcodeOp.INT_NEGATE -> {
                    var a = build(def.getInput(0), leaves, depth + 1);
                    return a == null ? null : new MbaExpr.Not(a);
                }
                case PcodeOp.INT_2COMP -> {
                    var a = build(def.getInput(0), leaves, depth + 1);
                    return a == null ? null : new MbaExpr.Neg(a);
                }
                default -> {  }
            }
        }
        return leaf(vn, leaves);
    }

    private interface BinCtor {
        MbaExpr make(MbaExpr a, MbaExpr b);
    }

    private static MbaExpr bin(BinCtor ctor, PcodeOp def, Map<String, Integer> leaves, int depth) {
        var a = build(def.getInput(0), leaves, depth + 1);
        var b = build(def.getInput(1), leaves, depth + 1);
        return a == null || b == null ? null : ctor.make(a, b);
    }

    private static MbaExpr leaf(Varnode vn, Map<String, Integer> leaves) {
        var key = leafKey(vn);
        var idx = leaves.computeIfAbsent(key, k -> leaves.size());
        return leaves.size() > LinearMba.MAX_VARS ? null : new MbaExpr.Var(idx);
    }

    private static String leafKey(Varnode vn) {
        var hv = vn.getHigh();
        if (hv != null && hv.getName() != null && !hv.getName().equals("UNNAMED")) return hv.getName();
        return "vn_" + vn.getAddress() + ":" + vn.getSize();
    }
}
