package io.github.imjustprism.ghidra.mcp.analysis.mba;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class PredicateExtract {

    public record Extracted(Predicate pred, int nvars, List<String> leaves) {}

    private PredicateExtract() {}

    public static Extracted fromCondition(Varnode cond) {
        var leaves = new LinkedHashMap<String, Integer>();
        var pred = build(cond, leaves, 0);
        if (pred == null || leaves.size() > LinearMba.MAX_VARS) return null;
        return new Extracted(pred, leaves.size(), new ArrayList<>(leaves.keySet()));
    }

    private static Predicate build(Varnode vn, Map<String, Integer> leaves, int depth) {
        if (vn == null || depth > 64) return null;
        var def = vn.getDef();
        if (def == null) return null;
        return switch (def.getOpcode()) {
            case PcodeOp.INT_EQUAL -> cmp(Predicate.Kind.EQ, def, leaves, depth);
            case PcodeOp.INT_NOTEQUAL -> cmp(Predicate.Kind.NE, def, leaves, depth);
            case PcodeOp.INT_SLESS -> cmp(Predicate.Kind.SLT, def, leaves, depth);
            case PcodeOp.INT_SLESSEQUAL -> cmp(Predicate.Kind.SLE, def, leaves, depth);
            case PcodeOp.INT_LESS -> cmp(Predicate.Kind.ULT, def, leaves, depth);
            case PcodeOp.INT_LESSEQUAL -> cmp(Predicate.Kind.ULE, def, leaves, depth);
            case PcodeOp.BOOL_AND -> combine(true, def, leaves, depth);
            case PcodeOp.BOOL_OR -> combine(false, def, leaves, depth);
            case PcodeOp.BOOL_NEGATE -> {
                var a = build(def.getInput(0), leaves, depth + 1);
                yield a == null ? null : new Predicate.Not(a);
            }
            default -> null;
        };
    }

    private static Predicate cmp(Predicate.Kind kind, PcodeOp def, Map<String, Integer> leaves, int depth) {
        var a = MbaExtract.build(def.getInput(0), leaves);
        var b = MbaExtract.build(def.getInput(1), leaves);
        return a == null || b == null ? null : new Predicate.Cmp(kind, a, b);
    }

    private static Predicate combine(boolean and, PcodeOp def, Map<String, Integer> leaves, int depth) {
        var a = build(def.getInput(0), leaves, depth + 1);
        var b = build(def.getInput(1), leaves, depth + 1);
        if (a == null || b == null) return null;
        return and ? new Predicate.And(a, b) : new Predicate.Or(a, b);
    }
}
