package io.github.imjustprism.ghidra.mcp.analysis.mba;

public sealed interface MbaExpr {

    record Var(int index) implements MbaExpr {}

    record Const(long value) implements MbaExpr {}

    record Not(MbaExpr a) implements MbaExpr {}

    record Neg(MbaExpr a) implements MbaExpr {}

    record And(MbaExpr a, MbaExpr b) implements MbaExpr {}

    record Or(MbaExpr a, MbaExpr b) implements MbaExpr {}

    record Xor(MbaExpr a, MbaExpr b) implements MbaExpr {}

    record Add(MbaExpr a, MbaExpr b) implements MbaExpr {}

    record Sub(MbaExpr a, MbaExpr b) implements MbaExpr {}

    record Mul(MbaExpr a, MbaExpr b) implements MbaExpr {}

    static long eval(MbaExpr e, long[] vars) {
        return switch (e) {
            case Var v -> vars[v.index()];
            case Const c -> c.value();
            case Not n -> ~eval(n.a(), vars);
            case Neg n -> -eval(n.a(), vars);
            case And b -> eval(b.a(), vars) & eval(b.b(), vars);
            case Or b -> eval(b.a(), vars) | eval(b.b(), vars);
            case Xor b -> eval(b.a(), vars) ^ eval(b.b(), vars);
            case Add b -> eval(b.a(), vars) + eval(b.b(), vars);
            case Sub b -> eval(b.a(), vars) - eval(b.b(), vars);
            case Mul b -> eval(b.a(), vars) * eval(b.b(), vars);
        };
    }

    static String render(MbaExpr e) {
        return switch (e) {
            case Var v -> "v" + v.index();
            case Const c -> Long.toString(c.value());
            case Not n -> "~" + render(n.a());
            case Neg n -> "-" + render(n.a());
            case And b -> "(" + render(b.a()) + " & " + render(b.b()) + ")";
            case Or b -> "(" + render(b.a()) + " | " + render(b.b()) + ")";
            case Xor b -> "(" + render(b.a()) + " ^ " + render(b.b()) + ")";
            case Add b -> "(" + render(b.a()) + " + " + render(b.b()) + ")";
            case Sub b -> "(" + render(b.a()) + " - " + render(b.b()) + ")";
            case Mul b -> "(" + render(b.a()) + " * " + render(b.b()) + ")";
        };
    }
}
