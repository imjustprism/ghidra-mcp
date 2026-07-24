package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Locale;
import java.util.Map;

public final class CfgObfuscation {

    private static final int MIN_FLATTENING_BLOCKS = 10;
    private static final double FLATTENING_RATIO = 0.30;

    private CfgObfuscation() {}

    public static String score(PluginContext ctx, String addr, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("No function at " + addr);
            var monitor = new ConsoleTaskMonitor();
            try {
                var blocks = collectBlocks(program, func, monitor);
                var body = func.getBody();
                int n = blocks.size();
                int edges = 0;
                int maxInDegree = 0;
                for (var b : blocks) {
                    edges += intraEdges(b.getDestinations(monitor), ref -> body.contains(ref.getDestinationAddress()));
                    int inDegree = intraEdges(b.getSources(monitor), ref -> body.contains(ref.getSourceAddress()));
                    if (inDegree > maxInDegree) maxInDegree = inDegree;
                }
                int cyclomatic = edges - n + 2;
                double dispatcherRatio = n > 0 ? (double) maxInDegree / n : 0;
                boolean flattened = n >= MIN_FLATTENING_BLOCKS && dispatcherRatio >= FLATTENING_RATIO;
                int complexityBonus = (int) Math.min(30L, Math.max(0L, cyclomatic) / 2L);
                int obfuscationScore = (int) Math.min(100, Math.round(dispatcherRatio * 100) + complexityBonus);

                var t = Responses.table(q, new String[]{"k", "v"}, 9);
                t.row("fn", func.getName());
                t.row("entry", Responses.addr(func.getEntryPoint()));
                t.row("blocks", n);
                t.row("edges", edges);
                t.row("cyclomatic", cyclomatic);
                t.row("max_in_degree", maxInDegree);
                t.row("dispatcher_ratio", String.format(Locale.ROOT, "%.2f", dispatcherRatio));
                t.row("score", obfuscationScore);
                t.row("likely_flattened", flattened);
                return t.build();
            } catch (CancelledException e) {
                throw new IllegalStateException("CFG analysis interrupted", e);
            }
        });
    }

    private static ArrayList<CodeBlock> collectBlocks(ghidra.program.model.listing.Program program,
                                                      Function func, TaskMonitor monitor) throws CancelledException {
        var blocks = new ArrayList<CodeBlock>();
        var it = new BasicBlockModel(program).getCodeBlocksContaining(func.getBody(), monitor);
        while (it.hasNext()) blocks.add(it.next());
        return blocks;
    }

    private interface RefFilter {
        boolean keep(ghidra.program.model.block.CodeBlockReference ref);
    }

    private static int intraEdges(ghidra.program.model.block.CodeBlockReferenceIterator it,
                                  RefFilter filter) throws CancelledException {
        int count = 0;
        while (it.hasNext()) {
            var ref = it.next();
            var ft = ref.getFlowType();
            if (ft != null && ft.isCall()) continue;
            if (filter.keep(ref)) count++;
        }
        return count;
    }
}
