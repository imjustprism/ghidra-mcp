package io.github.imjustprism.ghidra.mcp.analysis.mba;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class FindOpaque {

    private FindOpaque() {}

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
                var t = Responses.table(q, new String[]{"branch", "verdict", "predicate"}, 8);
                int branches = 0;
                int opaque = 0;
                for (var it = high.getPcodeOps(); it.hasNext(); ) {
                    var op = it.next();
                    if (op.getOpcode() != PcodeOp.CBRANCH || op.getNumInputs() < 2) continue;
                    branches++;
                    var ex = PredicateExtract.fromCondition(op.getInput(1));
                    if (ex == null) continue;
                    var verdict = Predicates.classify(ex.pred(), ex.nvars());
                    if (verdict == Predicates.Verdict.VARIABLE) continue;
                    opaque++;
                    t.row(Responses.addr(op.getSeqnum().getTarget()), verdict, Predicate.render(ex.pred()));
                }
                return "# opaque-predicate scan of " + func.getName() + " — " + branches
                        + " conditional branch(es), " + opaque + " opaque (heuristic: probe-based over"
                        + " the compared constants; confirm load-bearing hits with emulation/SMT)\n"
                        + t.total(opaque).build();
            } finally {
                decomp.dispose();
            }
        });
    }
}
