package io.github.imjustprism.ghidra.mcp.analysis.mba;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class LinearMbaTest {

    private static final MbaExpr X = new MbaExpr.Var(0);
    private static final MbaExpr Y = new MbaExpr.Var(1);
    private static final MbaExpr Z = new MbaExpr.Var(2);

    private static MbaExpr add(MbaExpr a, MbaExpr b) {
        return new MbaExpr.Add(a, b);
    }

    @Test
    void equivalenceHoldsForKnownMbaIdentity() {
        var mba = add(new MbaExpr.Xor(X, Y), new MbaExpr.Mul(new MbaExpr.Const(2), new MbaExpr.And(X, Y)));
        assertTrue(LinearMba.equivalent(mba, add(X, Y), 2));
    }

    @Test
    void equivalenceRejectsXorVersusAdd() {
        assertFalse(LinearMba.equivalent(new MbaExpr.Xor(X, Y), add(X, Y), 2));
    }

    @Test
    void simplifiesXorPlusTwoAndToSum() {
        var mba = add(new MbaExpr.Xor(X, Y), new MbaExpr.Mul(new MbaExpr.Const(2), new MbaExpr.And(X, Y)));
        var simplified = LinearMba.simplify(mba, 2);

        assertTrue(LinearMba.equivalent(simplified, add(X, Y), 2));
        assertEquals(2, LinearMba.termCount(simplified));
    }

    @Test
    void simplifiesOrPlusAndToSum() {
        var mba = add(new MbaExpr.Or(X, Y), new MbaExpr.And(X, Y));
        var simplified = LinearMba.simplify(mba, 2);

        assertTrue(LinearMba.equivalent(simplified, add(X, Y), 2));
        assertEquals(2, LinearMba.termCount(simplified));
    }

    @Test
    void simplifiesThreeVariableLinearMba() {
        var mba = add(add(new MbaExpr.Or(X, Y), Z), new MbaExpr.And(X, Y));
        var simplified = LinearMba.simplify(mba, 3);

        assertTrue(LinearMba.equivalent(simplified, add(add(X, Y), Z), 3));
    }

    @Test
    void declinesNonLinearMultiplication() {
        var nonLinear = new MbaExpr.Mul(X, Y);
        assertSame(nonLinear, LinearMba.simplify(nonLinear, 2));
    }
}
