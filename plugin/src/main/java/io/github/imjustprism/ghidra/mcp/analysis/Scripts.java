package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.app.script.GhidraScriptUtil;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class Scripts {

    private Scripts() {}

    public static String list(Page p, Map<String, String> q) {
        var t = Responses.table(p, q, new String[]{"script", "directory"});
        var w = new Responses.Window(p);
        for (var dir : GhidraScriptUtil.getScriptSourceDirectories()) {
            var files = dir.listFiles();
            if (files == null) continue;
            for (var f : files) {
                if (f.isDirectory()) continue;
                var name = f.getName();
                if (!name.endsWith(".java") && !name.endsWith(".py")) continue;
                if (!w.take()) continue;
                t.row(name, dir.getAbsolutePath());
            }
        }
        return t.total(w.total()).build();
    }
}
