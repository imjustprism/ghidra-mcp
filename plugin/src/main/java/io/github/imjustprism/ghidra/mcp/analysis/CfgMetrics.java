package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.HashMap;
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
                var index = new HashMap<Address, Integer>();
                for (int i = 0; i < n; i++) index.put(blocks.get(i).getFirstStartAddress(), i);
                var parent = new int[n];
                for (int i = 0; i < n; i++) parent[i] = i;

                int edges = 0;
                int conditionals = 0;
                int exits = 0;
                int backEdges = 0;
                for (int i = 0; i < n; i++) {
                    var b = blocks.get(i);
                    int outDegree = 0;
                    for (var d = b.getDestinations(monitor); d.hasNext(); ) {
                        var ref = d.next();
                        var ft = ref.getFlowType();
                        if (ft != null && ft.isCall()) continue;
                        var dest = ref.getDestinationAddress();
                        if (!body.contains(dest)) continue;
                        edges++;
                        outDegree++;
                        if (dest.compareTo(b.getFirstStartAddress()) < 0) backEdges++;
                        var di = index.get(dest);
                        if (di != null) union(parent, i, di);
                    }
                    if (outDegree == 0) exits++;
                    else if (outDegree > 1) conditionals++;
                }
                int components = 0;
                for (int i = 0; i < n; i++) {
                    if (find(parent, i) == i) components++;
                }
                int cyclomatic = n == 0 ? 0 : edges - n + 2 * components;

                var t = Responses.table(q, new String[]{"k", "v"}, 7);
                t.row("fn", func.getName());
                t.row("blocks", n);
                t.row("edges", edges);
                t.row("cyclomatic", cyclomatic);
                t.row("conditionals", conditionals);
                t.row("exits", exits);
                t.row("back_edges", backEdges);
                return t.build();
            } catch (CancelledException e) {
                throw new IllegalStateException("CFG analysis interrupted", e);
            }
        });
    }

    private static int find(int[] parent, int x) {
        while (parent[x] != x) {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        return x;
    }

    private static void union(int[] parent, int x, int y) {
        parent[find(parent, x)] = find(parent, y);
    }
}
