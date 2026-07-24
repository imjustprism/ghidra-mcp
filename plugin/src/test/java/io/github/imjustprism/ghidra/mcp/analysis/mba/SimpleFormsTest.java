package io.github.imjustprism.ghidra.mcp.analysis.mba;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SimpleFormsTest {

    private static final MbaExpr X = new MbaExpr.Var(0);
    private static final MbaExpr Y = new MbaExpr.Var(1);

    @Test
    void recognizesXorFromArithmeticForm() {

        var arith = new MbaExpr.Sub(new MbaExpr.Add(X, Y),
                new MbaExpr.Mul(new MbaExpr.Const(2), new MbaExpr.And(X, Y)));
        var simplest = SimpleForms.simplest(arith, 2);

        assertEquals(new MbaExpr.Xor(X, Y), simplest);
    }

    @Test
    void recognizesOrFromArithmeticForm() {

        var form = new MbaExpr.Add(new MbaExpr.And(X, Y), new MbaExpr.Xor(X, Y));
        var simplest = SimpleForms.simplest(form, 2);

        assertEquals(new MbaExpr.Or(X, Y), simplest);
    }

    @Test
    void keepsAlreadySimpleExpression() {
        var simplest = SimpleForms.simplest(new MbaExpr.Xor(X, Y), 2);
        assertTrue(LinearMba.nodeCount(simplest) <= LinearMba.nodeCount(new MbaExpr.Xor(X, Y)));
    }

    @Test
    void endToEndPipelineReducesObfuscatedXor() {

        var arith = new MbaExpr.Sub(new MbaExpr.Add(X, Y),
                new MbaExpr.Mul(new MbaExpr.Const(2), new MbaExpr.And(X, Y)));
        var out = MbaNormalize.normalize(SimpleForms.simplest(LinearMba.simplify(
                MbaNormalize.normalize(arith), 2), 2));
        assertEquals(new MbaExpr.Xor(X, Y), out);
        assertTrue(LinearMba.equivalent(out, arith, 2));
    }
}
