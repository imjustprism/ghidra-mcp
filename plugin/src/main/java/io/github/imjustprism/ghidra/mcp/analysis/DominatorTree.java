package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DominatorTree {

    private DominatorTree() {}

    public static String compute(PluginContext ctx, String addr, Page p, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("No function at " + addr);
            var body = func.getBody();
            var monitor = new ConsoleTaskMonitor();
            try {
                var blocks = new ArrayList<CodeBlock>();
                var bit = new BasicBlockModel(program).getCodeBlocksContaining(body, monitor);
                while (bit.hasNext()) blocks.add(bit.next());
                int n = blocks.size();

                var index = new HashMap<Address, Integer>();
                for (int i = 0; i < n; i++) index.put(blocks.get(i).getFirstStartAddress(), i);
                int entry = index.getOrDefault(func.getEntryPoint(), 0);

                List<List<Integer>> preds = new ArrayList<>();
                for (int i = 0; i < n; i++) preds.add(new ArrayList<>());
                for (int i = 0; i < n; i++) {
                    for (var d = blocks.get(i).getDestinations(monitor); d.hasNext(); ) {
                        var ref = d.next();
                        var ft = ref.getFlowType();
                        if (ft != null && ft.isCall()) continue;
                        var di = index.get(ref.getDestinationAddress());
                        if (di != null) preds.get(di).add(i);
                    }
                }

                var dom = new BitSet[n];
                for (int i = 0; i < n; i++) {
                    dom[i] = new BitSet(n);
                    if (i == entry) dom[i].set(entry);
                    else dom[i].set(0, n);
                }
                boolean changed = true;
                while (changed) {
                    changed = false;
                    for (int i = 0; i < n; i++) {
                        if (i == entry) continue;
                        BitSet next = null;
                        for (int pr : preds.get(i)) {
                            if (next == null) next = (BitSet) dom[pr].clone();
                            else next.and(dom[pr]);
                        }
                        if (next == null) next = new BitSet(n);
                        next.set(i);
                        if (!next.equals(dom[i])) {
                            dom[i] = next;
                            changed = true;
                        }
                    }
                }

                var t = Responses.table(p, q, new String[]{"block", "idom"});
                var w = new Responses.Window(p);
                for (int i = 0; i < n; i++) {
                    if (!w.take()) continue;
                    t.row(Responses.addr(blocks.get(i).getFirstStartAddress()), idom(dom, i, entry, blocks));
                }
                return t.total(w.total()).build();
            } catch (CancelledException e) {
                throw new IllegalStateException("CFG analysis interrupted", e);
            }
        });
    }

    private static String idom(BitSet[] dom, int i, int entry, ArrayList<CodeBlock> blocks) {
        if (i == entry) return "";
        int best = -1;
        int bestSize = -1;
        for (int d = dom[i].nextSetBit(0); d >= 0; d = dom[i].nextSetBit(d + 1)) {
            if (d == i) continue;
            int size = dom[d].cardinality();
            if (size > bestSize) {
                bestSize = size;
                best = d;
            }
        }
        return best >= 0 ? Responses.addr(blocks.get(best).getFirstStartAddress()) : "";
    }
}
