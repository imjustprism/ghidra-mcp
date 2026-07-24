package io.github.imjustprism.ghidra.mcp.analysis.mba;

public sealed interface Predicate {

    enum Kind { EQ, NE, SLT, SLE, ULT, ULE }

    record Cmp(Kind kind, MbaExpr a, MbaExpr b) implements Predicate {}

    record And(Predicate a, Predicate b) implements Predicate {}

    record Or(Predicate a, Predicate b) implements Predicate {}

    record Not(Predicate a) implements Predicate {}

    static boolean eval(Predicate p, long[] vars) {
        return switch (p) {
            case Cmp c -> {
                long x = MbaExpr.eval(c.a(), vars);
                long y = MbaExpr.eval(c.b(), vars);
                yield switch (c.kind()) {
                    case EQ -> x == y;
                    case NE -> x != y;
                    case SLT -> x < y;
                    case SLE -> x <= y;
                    case ULT -> Long.compareUnsigned(x, y) < 0;
                    case ULE -> Long.compareUnsigned(x, y) <= 0;
                };
            }
            case And a -> eval(a.a(), vars) && eval(a.b(), vars);
            case Or o -> eval(o.a(), vars) || eval(o.b(), vars);
            case Not n -> !eval(n.a(), vars);
        };
    }

    static String render(Predicate p) {
        return switch (p) {
            case Cmp c -> MbaExpr.render(c.a()) + " " + symbol(c.kind()) + " " + MbaExpr.render(c.b());
            case And a -> "(" + render(a.a()) + " && " + render(a.b()) + ")";
            case Or o -> "(" + render(o.a()) + " || " + render(o.b()) + ")";
            case Not n -> "!(" + render(n.a()) + ")";
        };
    }

    private static String symbol(Kind k) {
        return switch (k) {
            case EQ -> "==";
            case NE -> "!=";
            case SLT -> "<s";
            case SLE -> "<=s";
            case ULT -> "<u";
            case ULE -> "<=u";
        };
    }
}
