package io.github.imjustprism.ghidra.mcp.analysis.mba;

public final class Predicates {

    public enum Verdict { ALWAYS_TRUE, ALWAYS_FALSE, VARIABLE }

    private Predicates() {}

    public static Verdict classify(Predicate p, int nvars) {
        var probes = LinearMba.probeValues();
        var vars = new long[nvars];
        var state = new boolean[]{false, false, false}; // seen, sawTrue, sawFalse
        scan(p, probes, vars, 0, state);
        if (state[1] && state[2]) return Verdict.VARIABLE;
        return state[1] ? Verdict.ALWAYS_TRUE : Verdict.ALWAYS_FALSE;
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
