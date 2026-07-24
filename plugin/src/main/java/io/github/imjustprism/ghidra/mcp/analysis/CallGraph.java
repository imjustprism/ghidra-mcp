package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;

import java.util.HashMap;

public final class CallGraph {

    private CallGraph() {}

    public static String dot(PluginContext ctx, String addr, int depth) {
        if (depth < 0 || depth > 10) throw new IllegalArgumentException("Depth must be 0..10");
        return ctx.withAddress(addr, (program, a) -> {
            var root = Addresses.functionAtOrContaining(program, a);
            if (root == null) throw new IllegalArgumentException("No function at " + addr);
            var seen = new java.util.LinkedHashSet<Function>();
            var edges = new java.util.LinkedHashSet<String>();
            var queue = new java.util.ArrayDeque<Function>();
            var depths = new HashMap<Function, Integer>();
            queue.add(root);
            depths.put(root, 0);
            seen.add(root);
            var monitor = new ConsoleTaskMonitor();
            while (!queue.isEmpty()) {
                var f = queue.poll();
                int d = depths.getOrDefault(f, 0);
                if (d >= depth) continue;
                for (var callee : f.getCalledFunctions(monitor)) {
                    edges.add(dotId(f) + " -> " + dotId(callee));
                    if (!seen.contains(callee)) {
                        seen.add(callee);
                        depths.put(callee, d + 1);
                        queue.add(callee);
                    }
                }
            }
            var sb = new StringBuilder();
            sb.append("digraph callgraph {\n");
            for (var f : seen) {
                sb.append("  ").append(dotId(f))
                  .append(" [label=\"").append(escapeDot(f.getName()))
                  .append("\\n").append(f.getEntryPoint()).append("\"];\n");
            }
            for (var e : edges) sb.append("  ").append(e).append(";\n");
            sb.append("}\n");
            return sb.toString();
        });
    }

    public static String mermaid(PluginContext ctx, String addr, int depth,
            String direction, int maxNodes) {
        if (depth < 0 || depth > 10) throw new IllegalArgumentException("Depth must be 0..10");
        boolean callers = "callers".equals(direction) || "both".equals(direction);
        boolean callees = direction == null || direction.isBlank()
                || "callees".equals(direction) || "both".equals(direction);
        int cap = maxNodes <= 0 ? 60 : Math.min(maxNodes, 400);
        return ctx.withAddress(addr, (program, a) -> {
            var root = Addresses.functionAtOrContaining(program, a);
            if (root == null) throw new IllegalArgumentException("No function at " + addr);
            var seen = new java.util.LinkedHashSet<Function>();
            var edges = new java.util.LinkedHashSet<String>();
            var queue = new java.util.ArrayDeque<Function>();
            var depths = new HashMap<Function, Integer>();
            queue.add(root);
            depths.put(root, 0);
            seen.add(root);
            var monitor = new ConsoleTaskMonitor();
            boolean capped = false;
            while (!queue.isEmpty()) {
                var f = queue.poll();
                int d = depths.getOrDefault(f, 0);
                if (d >= depth) continue;
                if (callees) {
                    for (var callee : f.getCalledFunctions(monitor)) {
                        edges.add(nodeId(f) + " --> " + nodeId(callee));
                        if (seen.add(callee)) {
                            if (seen.size() > cap) { capped = true; break; }
                            depths.put(callee, d + 1);
                            queue.add(callee);
                        }
                    }
                }
                if (callers) {
                    for (var caller : f.getCallingFunctions(monitor)) {
                        edges.add(nodeId(caller) + " --> " + nodeId(f));
                        if (seen.add(caller)) {
                            if (seen.size() > cap) { capped = true; break; }
                            depths.put(caller, d + 1);
                            queue.add(caller);
                        }
                    }
                }
                if (capped) break;
            }
            var sb = new StringBuilder(256 + seen.size() * 48);
            sb.append("```mermaid\nflowchart LR\n");
            for (var f : seen) {
                sb.append("  ").append(nodeId(f)).append("[\"")
                  .append(escapeMermaid(f.getName())).append("\\n")
                  .append(f.getEntryPoint()).append("\"]");
                if (f == root) sb.append(":::root");
                sb.append('\n');
            }
            for (var e : edges) sb.append("  ").append(e).append('\n');
            sb.append("  classDef root fill:#cde,stroke:#06c,stroke-width:2px\n");
            sb.append("```\n");
            if (capped) sb.append("<!-- capped at ").append(cap).append(" nodes -->\n");
            return sb.toString();
        });
    }

    static String nodeId(Function f) {
        return "f_" + f.getEntryPoint().toString().replaceAll("[^A-Za-z0-9]", "_");
    }

    static String escapeMermaid(String s) {
        if (s == null) return "";
        return s.replace("\"", "&quot;").replace("\\", "/");
    }

    private static String dotId(Function f) {
        return "f_" + f.getEntryPoint().toString().replaceAll("[^A-Za-z0-9]", "_");
    }

    private static String escapeDot(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
