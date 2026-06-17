package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Map;

public final class CfgMetrics {

    private CfgMetrics() {}

    public static String metrics(PluginContext ctx, String addr, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("No function at " + addr);
            var body = func.getBody();
            var monitor = new ConsoleTaskMonitor();
            try {
                var blocks = new ArrayList<CodeBlock>();
                var it = new BasicBlockModel(program).getCodeBlocksContaining(body, monitor);
                while (it.hasNext()) blocks.add(it.next());

                int n = blocks.size();
                int edges = 0;
                int conditionals = 0;
                int exits = 0;
                int backEdges = 0;
                for (var b : blocks) {
                    int outDegree = 0;
                    for (var d = b.getDestinations(monitor); d.hasNext(); ) {
                        var ref = d.next();
                        var ft = ref.getFlowType();
                        if (ft != null && ft.isCall()) continue;
                        var dest = ref.getDestinationAddress();
                        if (!body.contains(dest)) continue;
                        edges++;
                        outDegree++;
                        if (dest.compareTo(b.getFirstStartAddress()) <= 0) backEdges++;
                    }
                    if (outDegree == 0) exits++;
                    else if (outDegree > 1) conditionals++;
                }

                var t = Responses.table(q, new String[]{"k", "v"}, 7);
                t.row("fn", func.getName());
                t.row("blocks", n);
                t.row("edges", edges);
                t.row("cyclomatic", edges - n + 2);
                t.row("conditionals", conditionals);
                t.row("exits", exits);
                t.row("back_edges", backEdges);
                return t.build();
            } catch (CancelledException e) {
                throw new IllegalStateException("CFG analysis interrupted", e);
            }
        });
    }
}
