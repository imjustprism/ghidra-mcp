package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;

public final class FuncsigGraph {

    public static final int DEFAULT_CAP = 80;
    public static final int MAX_CAP = 400;

    private static final String[] COLS = {"ns", "parent", "classes", "sigs"};

    private record Acc(int classes, int sigs) {}

    private FuncsigGraph() {}

    public static String graph(PluginContext ctx, String filter, String fmt, String maxStr,
            Page page, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var acc = new LinkedHashMap<String, Acc>();
            var classes = new LinkedHashSet<String>();
            for (var hit : NebulaStrings.defined(program, NebulaNames::isFuncsig)) {
                var owner = AssertProofs.ownerOf(hit.value());
                if (owner.isEmpty()) continue;
                if (!NebulaNames.namespaceMatches(owner, filter)) continue;
                if (classes.add(owner)) {
                    for (var ns : NebulaNames.namespaceChain(owner)) {
                        acc.merge(ns, new Acc(1, 1),
                                (a, b) -> new Acc(a.classes + b.classes, a.sigs + b.sigs));
                    }
                } else {
                    for (var ns : NebulaNames.namespaceChain(owner)) {
                        acc.merge(ns, new Acc(0, 1),
                                (a, b) -> new Acc(a.classes + b.classes, a.sigs + b.sigs));
                    }
                }
            }
            if (fmt != null && "tsv".equalsIgnoreCase(fmt)) {
                return tsv(acc, page, q);
            }
            return mermaid(acc, maxStr);
        });
    }

    private static String tsv(Map<String, Acc> acc, Page page, Map<String, String> q) {
        var names = new ArrayList<>(acc.keySet());
        names.sort(Comparator.naturalOrder());
        var t = Responses.table(q, COLS, Math.min(page.limit(), names.size()));
        var w = new Responses.Window(page);
        for (var ns : names) {
            if (!w.take()) continue;
            var a = acc.get(ns);
            t.row(ns, NebulaNames.parentNamespace(ns), a.classes, a.sigs);
        }
        return "# funcsig_graph namespaces=" + acc.size() + "\n"
                + "# this is the real Nebula module graph; Ghidra namespaces are DLLs and switchD_*\n"
                + t.total(w.total()).build();
    }

    private static String mermaid(Map<String, Acc> acc, String maxStr) {
        int cap = clamp(maxStr);
        var names = new ArrayList<>(acc.keySet());
        names.sort(Comparator
                .comparingInt((String s) -> -acc.get(s).sigs)
                .thenComparing(String::toString));
        var keep = new LinkedHashSet<String>();
        for (var ns : names) {
            if (keep.size() >= cap) break;
            keep.add(ns);
        }
        var sb = new StringBuilder(256 + keep.size() * 32);
        sb.append("```mermaid\nflowchart TD\n");
        int i = 0;
        var ids = new LinkedHashMap<String, String>();
        for (var ns : keep) {
            var id = "ns_" + i++;
            ids.put(ns, id);
            sb.append("  ").append(id).append("[\"")
              .append(CallGraph.escapeMermaid(ns))
              .append("\"]\n");
        }
        var edges = new LinkedHashSet<String>();
        for (var ns : keep) {
            var parent = NebulaNames.parentNamespace(ns);
            if (parent.isEmpty() || !ids.containsKey(parent)) continue;
            edges.add(ids.get(parent) + " --> " + ids.get(ns));
        }
        for (var e : edges) sb.append("  ").append(e).append('\n');
        sb.append("```\n");
        if (acc.size() > keep.size()) {
            sb.append("<!-- capped at ").append(cap).append(" of ").append(acc.size())
              .append(" namespaces -->\n");
        }
        return sb.toString();
    }

    private static int clamp(String maxStr) {
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
