package io.github.imjustprism.ghidra.mcp.analysis.mba;

import java.util.ArrayList;
import java.util.List;

public final class LinearMba {

    public static final int MAX_VARS = 4;

    private static final long[] PROBE_VALUES = {
        0L, -1L, 1L, 2L, 0x5555_5555_5555_5555L, -0x5555_5555_5555_5556L,
        0x0123_4567_89ab_cdefL, 0x7fff_ffff_ffff_ffffL
    };

    private LinearMba() {}

    public static boolean equivalent(MbaExpr a, MbaExpr b, int nvars) {
        var vars = new long[nvars];
        return probe(a, b, vars, 0);
    }

    private static boolean probe(MbaExpr a, MbaExpr b, long[] vars, int idx) {
        if (idx == vars.length) {
            return MbaExpr.eval(a, vars) == MbaExpr.eval(b, vars);
        }
        for (long val : PROBE_VALUES) {
            vars[idx] = val;
            if (!probe(a, b, vars, idx + 1)) return false;
        }
        return true;
    }

    public static MbaExpr simplify(MbaExpr expr, int nvars) {
        if (nvars < 1 || nvars > MAX_VARS) return expr;
        int n = 1 << nvars;
        long[] signature = new long[n];
        var vars = new long[nvars];
        for (int v = 0; v < n; v++) {
            for (int i = 0; i < nvars; i++) vars[i] = ((v >> i) & 1) != 0 ? -1L : 0L;
            signature[v] = MbaExpr.eval(expr, vars);
        }
        long constant = signature[0];
        long[] coeff = new long[n];
        for (int v = 1; v < n; v++) {
            long sub = 0;
            for (int s = (v - 1) & v; s > 0; s = (s - 1) & v) sub += coeff[s];
            coeff[v] = constant - signature[v] - sub;
        }
        var result = build(constant, coeff, nvars);
        return equivalent(result, expr, nvars) ? result : expr;
    }

    private static MbaExpr build(long constant, long[] coeff, int nvars) {
        var terms = new ArrayList<MbaExpr>();
        if (constant != 0) terms.add(new MbaExpr.Const(constant));
        for (int v = 1; v < coeff.length; v++) {
            if (coeff[v] == 0) continue;
            terms.add(scale(coeff[v], conjunction(v, nvars)));
        }
        if (terms.isEmpty()) return new MbaExpr.Const(0);
        var acc = terms.get(0);
        for (int i = 1; i < terms.size(); i++) acc = new MbaExpr.Add(acc, terms.get(i));
        return acc;
    }

    private static MbaExpr scale(long c, MbaExpr term) {
        if (c == 1) return term;
        if (c == -1) return new MbaExpr.Neg(term);
        return new MbaExpr.Mul(new MbaExpr.Const(c), term);
    }

    private static MbaExpr conjunction(int mask, int nvars) {
        MbaExpr acc = null;
        for (int i = 0; i < nvars; i++) {
            if ((mask & (1 << i)) == 0) continue;
            var v = new MbaExpr.Var(i);
            acc = acc == null ? v : new MbaExpr.And(acc, v);
        }
        return acc;
    }

    public static int termCount(MbaExpr e) {
        var terms = new ArrayList<MbaExpr>();
        flatten(e, terms);
        return terms.size();
    }

    private static void flatten(MbaExpr e, List<MbaExpr> out) {
        if (e instanceof MbaExpr.Add a) {
            flatten(a.a(), out);
            flatten(a.b(), out);
        } else {
            out.add(e);
        }
    }
}
