package io.github.imjustprism.ghidra.mcp.analysis.mba;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class MbaNormalizeTest {

    private static final MbaExpr X = new MbaExpr.Var(0);

    @Test
    void doubleNotCancels() {
        assertEquals(X, MbaNormalize.normalize(new MbaExpr.Not(new MbaExpr.Not(X))));
    }

    @Test
    void xorWithSelfIsZero() {
        assertEquals(new MbaExpr.Const(0), MbaNormalize.normalize(new MbaExpr.Xor(X, X)));
    }

    @Test
    void andWithAllOnesIsIdentity() {
        assertEquals(X, MbaNormalize.normalize(new MbaExpr.And(X, new MbaExpr.Const(-1))));
    }

    @Test
    void foldsConstantArithmetic() {
        assertEquals(new MbaExpr.Const(7),
                MbaNormalize.normalize(new MbaExpr.Add(new MbaExpr.Const(3), new MbaExpr.Const(4))));
    }

    @Test
    void multiplyByZeroIsZero() {
        assertEquals(new MbaExpr.Const(0), MbaNormalize.normalize(new MbaExpr.Mul(X, new MbaExpr.Const(0))));
    }

    @Test
    void nestedAddZeroThenXorSelfCollapses() {
        var e = new MbaExpr.Xor(new MbaExpr.Add(X, new MbaExpr.Const(0)), X);
        assertEquals(new MbaExpr.Const(0), MbaNormalize.normalize(e));
    }

    @Test
    void preservesSemantics() {
        var e = new MbaExpr.Xor(new MbaExpr.Const(-1), new MbaExpr.And(X, new MbaExpr.Const(-1)));
        assertTrue(LinearMba.equivalent(e, MbaNormalize.normalize(e), 1));
    }
}
