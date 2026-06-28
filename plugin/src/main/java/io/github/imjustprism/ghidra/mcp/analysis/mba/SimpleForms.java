package io.github.imjustprism.ghidra.mcp.analysis.mba;

import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.And;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Add;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Const;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Not;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Or;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Sub;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Var;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Xor;

import java.util.ArrayList;
import java.util.List;

public final class SimpleForms {

    private SimpleForms() {}

    public static MbaExpr simplest(MbaExpr expr, int nvars) {
        if (nvars < 1 || nvars > 2) return expr;
        var best = expr;
        int bestNodes = LinearMba.nodeCount(expr);
        for (var cand : library(nvars)) {
            int n = LinearMba.nodeCount(cand);
            if (n < bestNodes && LinearMba.equivalent(cand, expr, nvars)) {
                best = cand;
                bestNodes = n;
            }
        }
        return best;
    }

    private static List<MbaExpr> library(int nvars) {
        var x = new Var(0);
        var out = new ArrayList<MbaExpr>();
        out.add(new Const(0));
        out.add(new Const(-1));
        out.add(x);
        out.add(new Not(x));
        out.add(new MbaExpr.Neg(x));
        if (nvars == 1) return out;
        var y = new Var(1);
        out.add(y);
        out.add(new Not(y));
        out.add(new And(x, y));
        out.add(new Or(x, y));
        out.add(new Xor(x, y));
        out.add(new Not(new Xor(x, y)));
        out.add(new Not(new And(x, y)));
        out.add(new Not(new Or(x, y)));
        out.add(new And(x, new Not(y)));
        out.add(new And(new Not(x), y));
        out.add(new Or(x, new Not(y)));
        out.add(new Or(new Not(x), y));
        out.add(new Add(x, y));
        out.add(new Sub(x, y));
        out.add(new Sub(y, x));
        return out;
    }
}
