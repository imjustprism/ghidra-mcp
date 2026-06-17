package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

public final class XrefGraph {

    private static final int DEFAULT_CAP = 40;
    private static final int MAX_CAP = 200;

    private XrefGraph() {}

    public static String mermaid(PluginContext ctx, String addr, int max) {
        int cap = max <= 0 ? DEFAULT_CAP : Math.min(max, MAX_CAP);
        return ctx.withAddress(addr, (program, a) -> {
            var refs = program.getReferenceManager();
            var fm = program.getFunctionManager();
            var nodes = new LinkedHashMap<String, String>();
            var edges = new LinkedHashSet<String>();
            var centerId = nodeId(a);
            nodes.put(centerId, label(program, fm, a));
            boolean capped = false;

            var inbound = refs.getReferencesTo(a);
            while (inbound.hasNext()) {
                var r = inbound.next();
                var from = r.getFromAddress();
                if (!from.isMemoryAddress()) continue;
                var id = nodeId(from);
                if (nodes.size() >= cap && !nodes.containsKey(id)) { capped = true; break; }
                nodes.putIfAbsent(id, label(program, fm, from));
                edges.add(id + " -->|" + r.getReferenceType().getName() + "| " + centerId);
            }
            for (var r : refs.getReferencesFrom(a)) {
                if (capped) break;
                var to = r.getToAddress();
                if (!to.isMemoryAddress()) continue;
                var id = nodeId(to);
                if (nodes.size() >= cap && !nodes.containsKey(id)) { capped = true; break; }
                nodes.putIfAbsent(id, label(program, fm, to));
                edges.add(centerId + " -->|" + r.getReferenceType().getName() + "| " + id);
            }

            var sb = new StringBuilder(256 + nodes.size() * 48);
            sb.append("```mermaid\nflowchart LR\n");
            for (var e : nodes.entrySet()) {
                sb.append("  ").append(e.getKey()).append("[\"").append(e.getValue()).append("\"]");
                if (e.getKey().equals(centerId)) sb.append(":::center");
                sb.append('\n');
            }
            for (var e : edges) sb.append("  ").append(e).append('\n');
            sb.append("  classDef center fill:#cde,stroke:#06c,stroke-width:2px\n```\n");
            if (capped) sb.append("<!-- capped at ").append(cap).append(" nodes -->\n");
            return sb.toString();
        });
    }

    private static String nodeId(Address a) {
        return "n_" + a.toString().replaceAll("[^A-Za-z0-9]", "_");
    }

    private static String label(Program program, FunctionManager fm, Address a) {
        var fn = fm.getFunctionContaining(a);
        String name = "";
        if (fn != null) {
            name = fn.getName();
        } else {
            var data = program.getListing().getDataAt(a);
            if (data != null && data.getLabel() != null) name = data.getLabel();
        }
        return CallGraph.escapeMermaid(name) + "\\n" + a;
    }
}
