package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.LinkedHashSet;

public final class Cfg {

    private Cfg() {}

    public static String mermaid(PluginContext ctx, String addr) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("No function at " + addr);
            var model = new BasicBlockModel(program);
            var monitor = new ConsoleTaskMonitor();
            var nodes = new LinkedHashSet<String>();
            var sb = new StringBuilder(512);
            sb.append("```mermaid\nflowchart TD\n");
            try {
                var blocks = model.getCodeBlocksContaining(func.getBody(), monitor);
                while (blocks.hasNext()) {
                    var block = blocks.next();
                    String id = blockId(block);
                    if (nodes.add(id)) {
                        sb.append("  ").append(id).append("[\"")
                          .append(Responses.addr(block.getFirstStartAddress())).append("\"]\n");
                    }
                    var dests = block.getDestinations(monitor);
                    while (dests.hasNext()) {
                        var ref = dests.next();
                        var dest = ref.getDestinationBlock();
                        if (dest == null) continue;
                        var ft = ref.getFlowType();
                        if (ft != null && ft.isCall()) continue;
                        String label = edgeLabel(ft);
                        sb.append("  ").append(id).append(label.isEmpty() ? " --> " : " -->|" + label + "| ")
                          .append(blockId(dest)).append('\n');
                    }
                }
            } catch (Exception e) {
                throw new IllegalStateException("Error building CFG: " + e.getMessage(), e);
            }
            sb.append("```\n");
            return sb.toString();
        });
    }

    private static String edgeLabel(ghidra.program.model.symbol.FlowType ft) {
        if (ft == null) return "";
        if (ft.isConditional() && ft.isJump()) return "true";
        if (ft.isJump()) return "jmp";
        return "";
    }

    private static String blockId(CodeBlock block) {
        return "b_" + block.getFirstStartAddress().toString().replaceAll("[^A-Za-z0-9]", "_");
    }
}
