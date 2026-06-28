package io.github.imjustprism.ghidra.mcp.analysis.mba;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.task.TaskMonitor;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class MbaSimplify {

    private MbaSimplify() {}

    public static String run(PluginContext ctx, String addr, Map<String, String> q) {
        if (addr == null || addr.isBlank()) throw new IllegalArgumentException("address is required");
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("no function at or containing " + addr);
            var decomp = new DecompInterface();
            decomp.openProgram(program);
            try {
                var res = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY);
                var high = res == null ? null : res.getHighFunction();
                if (high == null) return "decompilation failed for " + func.getName();
                PcodeOpAST chosen = null;
                for (var it = high.getPcodeOps(a); it.hasNext(); ) {
                    var op = it.next();
                    if (op.getOutput() != null && isArith(op.getOpcode())) chosen = op;
                }
                if (chosen == null) {
                    return "no arithmetic/bitwise expression at " + addr
                            + " (point at an INT_ADD/SUB/MULT/AND/OR/XOR/NEGATE site)";
                }
                var ex = MbaExtract.fromVarnode(chosen.getOutput());
                if (ex == null) {
                    return "expression unsupported: more than " + LinearMba.MAX_VARS
                            + " distinct variables or non-arithmetic ops in the tree";
                }
                var normalized = MbaNormalize.normalize(ex.expr());
                var simplified = MbaNormalize.normalize(LinearMba.simplify(normalized, ex.nvars()));
                var origRender = MbaExpr.render(ex.expr());
                var simpRender = MbaExpr.render(simplified);
                var sb = new StringBuilder();
                sb.append("# simplify_expression @ ").append(Responses.addr(a))
                        .append(" in ").append(func.getName()).append('\n');
                for (int i = 0; i < ex.leaves().size(); i++) {
                    sb.append("# v").append(i).append(" = ").append(ex.leaves().get(i)).append('\n');
                }
                sb.append("original  = ").append(origRender).append('\n');
                sb.append("simplified= ").append(simpRender).append('\n');
                if (origRender.equals(simpRender)) {
                    sb.append("# unchanged (already minimal, or not a linear MBA over these variables)\n");
                }
                return sb.toString();
            } finally {
                decomp.dispose();
            }
        });
    }

    private static boolean isArith(int op) {
        return switch (op) {
            case PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT, PcodeOp.INT_AND,
                    PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.INT_NEGATE, PcodeOp.INT_2COMP -> true;
            default -> false;
        };
    }
}
