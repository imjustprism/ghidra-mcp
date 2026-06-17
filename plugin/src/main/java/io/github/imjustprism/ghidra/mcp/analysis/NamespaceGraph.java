package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.GlobalNamespace;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

public final class NamespaceGraph {

    private static final int DEFAULT_CAP = 80;
    private static final int MAX_CAP = 400;

    private NamespaceGraph() {}

    public static String mermaid(PluginContext ctx, String maxStr) {
        int cap = clampCap(maxStr);
        return ctx.withProgram(program -> {
            var nodes = new LinkedHashMap<String, String>();
            var edgePairs = new ArrayList<String[]>();
            var processed = new HashSet<Long>();
            boolean capped = false;
            for (var s : program.getSymbolTable().getAllSymbols(true)) {
                if (capped) break;
                var ns = s.getParentNamespace();
                while (ns != null && !(ns instanceof GlobalNamespace)) {
                    if (!processed.add(ns.getID())) break;
                    if (nodes.size() >= cap) { capped = true; break; }
                    var id = "ns_" + ns.getID();
                    nodes.put(id, CallGraph.escapeMermaid(ns.getName()));
                    var parent = ns.getParentNamespace();
                    if (parent != null && !(parent instanceof GlobalNamespace)) {
                        edgePairs.add(new String[]{"ns_" + parent.getID(), id});
                    }
                    ns = parent;
                }
            }
            var edges = new LinkedHashSet<String>();
            for (var pair : edgePairs) {
                if (nodes.containsKey(pair[0])) edges.add(pair[0] + " --> " + pair[1]);
            }

            var sb = new StringBuilder(256 + nodes.size() * 32);
            sb.append("```mermaid\nflowchart TD\n");
            for (var e : nodes.entrySet()) {
                sb.append("  ").append(e.getKey()).append("[\"").append(e.getValue()).append("\"]\n");
            }
            for (var e : edges) sb.append("  ").append(e).append('\n');
            sb.append("```\n");
            if (capped) sb.append("<!-- capped at ").append(cap).append(" namespaces -->\n");
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
}
