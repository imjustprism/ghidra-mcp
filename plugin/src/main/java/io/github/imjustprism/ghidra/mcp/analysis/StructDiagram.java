package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;

import java.util.HashMap;
import java.util.LinkedHashSet;

public final class StructDiagram {

    private static final int MAX_FIELDS = 20;

    private StructDiagram() {}

    public static String mermaid(PluginContext ctx, String filter, int max) {
        int cap = max <= 0 ? 40 : Math.min(max, 200);
        return ctx.requireProgram(() -> {
            var program = ctx.currentProgram();
            var dtm = program.getDataTypeManager();
            var structs = new java.util.ArrayList<Structure>();
            var byName = new HashMap<String, String>();
            var it = dtm.getAllStructures();
            while (it.hasNext() && structs.size() < cap) {
                var s = it.next();
                if (filter != null && !filter.isBlank()
                        && !s.getName().toLowerCase().contains(filter.toLowerCase())) {
                    continue;
                }
                structs.add(s);
                byName.put(s.getName(), classId(s.getName()));
            }
            if (structs.isEmpty()) return "No structures" + (filter != null ? " matching '" + filter + "'" : "");
            var edges = new LinkedHashSet<String>();
            var sb = new StringBuilder(256 + structs.size() * 96);
            sb.append("```mermaid\nclassDiagram\n");
            for (var s : structs) {
                String id = byName.get(s.getName());
                sb.append("  class ").append(id).append("[\"").append(s.getName()).append("\"] {\n");
                int n = 0;
                for (var c : s.getDefinedComponents()) {
                    if (n++ >= MAX_FIELDS) {
                        sb.append("    +.. more\n");
                        break;
                    }
                    var dt = c.getDataType();
                    String field = c.getFieldName() == null ? "field_" + c.getOffset() : c.getFieldName();
                    sb.append("    +").append(token(dt.getName())).append(' ').append(token(field)).append('\n');
                    var target = baseStruct(dt);
                    if (target != null && byName.containsKey(target.getName())) {
                        edges.add(id + " --> " + byName.get(target.getName()) + " : " + token(field));
                    }
                }
                sb.append("  }\n");
            }
            for (var e : edges) sb.append("  ").append(e).append('\n');
            sb.append("```\n");
            return sb.toString();
        });
    }

    private static Structure baseStruct(DataType dt) {
        DataType cur = dt;
        if (cur instanceof Pointer p) cur = p.getDataType();
        return cur instanceof Structure s ? s : null;
    }

    private static String classId(String name) {
        return "S_" + name.replaceAll("[^A-Za-z0-9]", "_");
    }

    private static String token(String s) {
        if (s == null || s.isEmpty()) return "_";
        return s.replaceAll("[^A-Za-z0-9_]", "_");
    }
}
