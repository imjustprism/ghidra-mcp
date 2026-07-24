package io.github.imjustprism.ghidra.mcp.analysis.mba;

import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Add;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.And;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Const;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Mul;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Neg;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Not;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Or;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Sub;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Var;
import io.github.imjustprism.ghidra.mcp.analysis.mba.MbaExpr.Xor;

public final class MbaNormalize {

    private static final int MAX_ROUNDS = 32;

    private MbaNormalize() {}

    public static MbaExpr normalize(MbaExpr e) {
        var cur = e;
        for (int i = 0; i < MAX_ROUNDS; i++) {
            var next = step(cur);
            if (next.equals(cur)) return next;
            cur = next;
        }
        return cur;
    }

    private static MbaExpr step(MbaExpr e) {
        return switch (e) {
            case Var v -> v;
            case Const c -> c;
            case Not n -> simplifyNot(step(n.a()));
            case Neg n -> simplifyNeg(step(n.a()));
            case And b -> simplifyAnd(step(b.a()), step(b.b()));
            case Or b -> simplifyOr(step(b.a()), step(b.b()));
            case Xor b -> simplifyXor(step(b.a()), step(b.b()));
            case Add b -> simplifyAdd(step(b.a()), step(b.b()));
            case Sub b -> simplifySub(step(b.a()), step(b.b()));
            case Mul b -> simplifyMul(step(b.a()), step(b.b()));
        };
    }

    private static MbaExpr simplifyNot(MbaExpr a) {
        if (a instanceof Const c) return new Const(~c.value());
        if (a instanceof Not n) return n.a();
        return new Not(a);
    }

    private static MbaExpr simplifyNeg(MbaExpr a) {
        if (a instanceof Const c) return new Const(-c.value());
        if (a instanceof Neg n) return n.a();
        return new Neg(a);
    }

    private static MbaExpr simplifyAnd(MbaExpr a, MbaExpr b) {
        if (a instanceof Const x && b instanceof Const y) return new Const(x.value() & y.value());
        if (isConst(a, 0) || isConst(b, 0)) return new Const(0);
        if (isConst(a, -1)) return b;
        if (isConst(b, -1)) return a;
        if (a.equals(b)) return a;
        return new And(a, b);
    }

    private static MbaExpr simplifyOr(MbaExpr a, MbaExpr b) {
        if (a instanceof Const x && b instanceof Const y) return new Const(x.value() | y.value());
        if (isConst(a, -1) || isConst(b, -1)) return new Const(-1);
        if (isConst(a, 0)) return b;
        if (isConst(b, 0)) return a;
        if (a.equals(b)) return a;
        return new Or(a, b);
    }

    private static MbaExpr simplifyXor(MbaExpr a, MbaExpr b) {
        if (a instanceof Const x && b instanceof Const y) return new Const(x.value() ^ y.value());
        if (isConst(a, 0)) return b;
        if (isConst(b, 0)) return a;
        if (isConst(a, -1)) return simplifyNot(b);
        if (isConst(b, -1)) return simplifyNot(a);
        if (a.equals(b)) return new Const(0);
        return new Xor(a, b);
    }

    private static MbaExpr simplifyAdd(MbaExpr a, MbaExpr b) {
        if (a instanceof Const x && b instanceof Const y) return new Const(x.value() + y.value());
        if (isConst(a, 0)) return b;
        if (isConst(b, 0)) return a;
        return new Add(a, b);
    }

    private static MbaExpr simplifySub(MbaExpr a, MbaExpr b) {
        if (a instanceof Const x && b instanceof Const y) return new Const(x.value() - y.value());
        if (isConst(b, 0)) return a;
        if (a.equals(b)) return new Const(0);
        return new Sub(a, b);
    }

    private static MbaExpr simplifyMul(MbaExpr a, MbaExpr b) {
        if (a instanceof Const x && b instanceof Const y) return new Const(x.value() * y.value());
        if (isConst(a, 0) || isConst(b, 0)) return new Const(0);
        if (isConst(a, 1)) return b;
        if (isConst(b, 1)) return a;
        if (isConst(a, -1)) return simplifyNeg(b);
        if (isConst(b, -1)) return simplifyNeg(a);
        return new Mul(a, b);
    }

    private static boolean isConst(MbaExpr e, long v) {
        return e instanceof Const c && c.value() == v;
    }
}
