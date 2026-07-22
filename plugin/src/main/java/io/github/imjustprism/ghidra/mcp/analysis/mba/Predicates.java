package io.github.imjustprism.ghidra.mcp.analysis.mba;

import java.util.LinkedHashSet;
import java.util.Set;

public final class Predicates {

    public enum Verdict { ALWAYS_TRUE, ALWAYS_FALSE, VARIABLE }

    private static final int MAX_PROBES = 40;

    private Predicates() {}

    public static Verdict classify(Predicate p, int nvars) {
        var probes = probeSet(p);
        var vars = new long[nvars];
        var state = new boolean[]{false, false, false};
        scan(p, probes, vars, 0, state);
        if (state[1] && state[2]) return Verdict.VARIABLE;
        return state[1] ? Verdict.ALWAYS_TRUE : Verdict.ALWAYS_FALSE;
    }

    private static long[] probeSet(Predicate p) {
        var values = new LinkedHashSet<Long>();
        for (long v : LinearMba.probeValues()) values.add(v);
        var consts = new LinkedHashSet<Long>();
        collect(p, consts);
        for (long c : consts) {
            values.add(c);
            values.add(c + 1);
            values.add(c - 1);
            if (values.size() >= MAX_PROBES) break;
        }
        return values.stream().mapToLong(Long::longValue).toArray();
    }

    private static void collect(Predicate p, Set<Long> out) {
        switch (p) {
            case Predicate.Cmp c -> {
                collect(c.a(), out);
                collect(c.b(), out);
            }
            case Predicate.And a -> {
                collect(a.a(), out);
                collect(a.b(), out);
            }
            case Predicate.Or o -> {
                collect(o.a(), out);
                collect(o.b(), out);
            }
            case Predicate.Not n -> collect(n.a(), out);
        }
    }

    private static void collect(MbaExpr e, Set<Long> out) {
        switch (e) {
            case MbaExpr.Const c -> out.add(c.value());
            case MbaExpr.Var v -> { }
            case MbaExpr.Not n -> collect(n.a(), out);
            case MbaExpr.Neg n -> collect(n.a(), out);
            case MbaExpr.And b -> { collect(b.a(), out); collect(b.b(), out); }
            case MbaExpr.Or b -> { collect(b.a(), out); collect(b.b(), out); }
            case MbaExpr.Xor b -> { collect(b.a(), out); collect(b.b(), out); }
            case MbaExpr.Add b -> { collect(b.a(), out); collect(b.b(), out); }
            case MbaExpr.Sub b -> { collect(b.a(), out); collect(b.b(), out); }
            case MbaExpr.Mul b -> { collect(b.a(), out); collect(b.b(), out); }
        }
    }

    public static boolean isOpaque(Predicate p, int nvars) {
        return classify(p, nvars) != Verdict.VARIABLE;
    }

    private static void scan(Predicate p, long[] probes, long[] vars, int idx, boolean[] state) {
        if (state[1] && state[2]) return;
        if (idx == vars.length) {
            if (Predicate.eval(p, vars)) state[1] = true;
            else state[2] = true;
            return;
        }
        for (long v : probes) {
            vars[idx] = v;
            scan(p, probes, vars, idx + 1, state);
            if (state[1] && state[2]) return;
        }
    }
}
