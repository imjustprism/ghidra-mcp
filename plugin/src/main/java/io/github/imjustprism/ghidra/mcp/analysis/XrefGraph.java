package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

public final class XrefGraph {

    private static final int DEFAULT_CAP = 40;
    private static final int MAX_CAP = 200;

    private XrefGraph() {}

    public static String mermaid(PluginContext ctx, String addr, String maxStr) {
        int cap = clampCap(maxStr);
        return ctx.withAddress(addr, (program, a) -> {
            var refs = program.getReferenceManager();
            var fm = program.getFunctionManager();
            var nodes = new LinkedHashMap<String, String>();
            var edges = new LinkedHashSet<String>();
            var centerId = nodeId(a);
            nodes.put(centerId, label(program, fm, a));

            var outRefs = new ArrayList<Reference>();
            for (var r : refs.getReferencesFrom(a)) {
                if (outRefs.size() >= cap) break;
                outRefs.add(r);
            }
            var inRefs = new ArrayList<Reference>();
            var inbound = refs.getReferencesTo(a);
            while (inbound.hasNext() && inRefs.size() < cap) inRefs.add(inbound.next());

            int oi = 0;
            int ii = 0;
            int added = 0;
            while (added < cap && (oi < outRefs.size() || ii < inRefs.size())) {
                if (oi < outRefs.size()) {
                    var r = outRefs.get(oi++);
                    var to = r.getToAddress();
                    var id = nodeId(to);
                    nodes.putIfAbsent(id, label(program, fm, to));
                    edges.add(centerId + " -->|" + r.getReferenceType().getName() + "| " + id);
                    if (++added >= cap) break;
                }
                if (ii < inRefs.size()) {
                    var r = inRefs.get(ii++);
                    var from = r.getFromAddress();
                    var id = nodeId(from);
                    nodes.putIfAbsent(id, label(program, fm, from));
                    edges.add(id + " -->|" + r.getReferenceType().getName() + "| " + centerId);
                    added++;
                }
            }
            boolean capped = oi < outRefs.size() || ii < inRefs.size();

            var sb = new StringBuilder(256 + nodes.size() * 48);
            sb.append("```mermaid\nflowchart LR\n");
            for (var e : nodes.entrySet()) {
                sb.append("  ").append(e.getKey()).append("[\"").append(e.getValue()).append("\"]");
                if (e.getKey().equals(centerId)) sb.append(":::center");
                sb.append('\n');
            }
            for (var e : edges) sb.append("  ").append(e).append('\n');
            sb.append("  classDef center fill:#cde,stroke:#06c,stroke-width:2px\n```\n");
            if (capped) sb.append("<!-- capped at ").append(cap).append(" edges -->\n");
            return sb.toString();
        });
    }

    private static int clampCap(String maxStr) {
        if (maxStr == null || maxStr.isBlank()) return DEFAULT_CAP;
        try {
            long m = Long.parseLong(maxStr.trim());
            if (m <= 0) return DEFAULT_CAP;
            return (int) Math.min(m, MAX_CAP);
        } catch (NumberFormatException e) {
            return DEFAULT_CAP;
        }
    }

    private static String nodeId(Address a) {
        return "n_" + a.toString().replaceAll("[^A-Za-z0-9]", "_");
    }

    private static String label(Program program, FunctionManager fm, Address a) {
        var fn = fm.getFunctionContaining(a);
        if (fn != null) return CallGraph.escapeMermaid(fn.getName()) + "\\n" + a;
        var sym = program.getSymbolTable().getPrimarySymbol(a);
        String name = sym != null ? sym.getName() : "";
        if (name.isEmpty()) {
            var data = program.getListing().getDataContaining(a);
            if (data != null && data.getLabel() != null) name = data.getLabel();
        }
        return CallGraph.escapeMermaid(name) + "\\n" + a;
    }
}
