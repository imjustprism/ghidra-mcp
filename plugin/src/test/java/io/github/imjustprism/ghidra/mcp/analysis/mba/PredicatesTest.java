package io.github.imjustprism.ghidra.mcp.analysis.mba;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PredicatesTest {

    private static final MbaExpr X = new MbaExpr.Var(0);
    private static final MbaExpr Y = new MbaExpr.Var(1);

    private static MbaExpr c(long v) {
        return new MbaExpr.Const(v);
    }

    @Test
    void productOfConsecutiveIsAlwaysEven() {
        // x*(x+1) & 1 == 0  -> always true
        var lhs = new MbaExpr.And(new MbaExpr.Mul(X, new MbaExpr.Add(X, c(1))), c(1));
        var p = new Predicate.Cmp(Predicate.Kind.EQ, lhs, c(0));
        assertEquals(Predicates.Verdict.ALWAYS_TRUE, Predicates.classify(p, 1));
        assertTrue(Predicates.isOpaque(p, 1));
    }

    @Test
    void orWithOneIsNeverZero() {
        // (x | 1) == 0  -> always false
        var p = new Predicate.Cmp(Predicate.Kind.EQ, new MbaExpr.Or(X, c(1)), c(0));
        assertEquals(Predicates.Verdict.ALWAYS_FALSE, Predicates.classify(p, 1));
        assertTrue(Predicates.isOpaque(p, 1));
    }

    @Test
    void selfEqualityIsAlwaysTrue() {
        var p = new Predicate.Cmp(Predicate.Kind.EQ, X, X);
        assertEquals(Predicates.Verdict.ALWAYS_TRUE, Predicates.classify(p, 1));
    }

    @Test
    void genuineComparisonIsVariable() {
        var p = new Predicate.Cmp(Predicate.Kind.SLT, X, Y);
        assertEquals(Predicates.Verdict.VARIABLE, Predicates.classify(p, 2));
        assertFalse(Predicates.isOpaque(p, 2));
    }

    @Test
    void characterComparisonAgainstConstantIsNotOpaque() {
        // v0 == 91 ('[') is a genuine branch; the constant must enter the probe set
        // or it reads as ALWAYS_FALSE. Regression for the URL-parser false positives.
        assertEquals(Predicates.Verdict.VARIABLE,
                Predicates.classify(new Predicate.Cmp(Predicate.Kind.EQ, X, c(91)), 1));
        assertEquals(Predicates.Verdict.VARIABLE,
                Predicates.classify(new Predicate.Cmp(Predicate.Kind.NE, X, c(58)), 1));
        assertEquals(Predicates.Verdict.VARIABLE,
                Predicates.classify(new Predicate.Cmp(Predicate.Kind.ULT, X, c(47)), 1));
    }

    @Test
    void booleanCombinatorsEvaluate() {
        // (x == x) || (x <s y)  -> always true; !(x == x) -> always false
        var tru = new Predicate.Cmp(Predicate.Kind.EQ, X, X);
        var lt = new Predicate.Cmp(Predicate.Kind.SLT, X, Y);
        assertEquals(Predicates.Verdict.ALWAYS_TRUE, Predicates.classify(new Predicate.Or(tru, lt), 2));
        assertEquals(Predicates.Verdict.ALWAYS_FALSE, Predicates.classify(new Predicate.Not(tru), 1));
    }
}
