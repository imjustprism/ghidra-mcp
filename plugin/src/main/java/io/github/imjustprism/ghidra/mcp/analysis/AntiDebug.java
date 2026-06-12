package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.hashes.Hashes;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class AntiDebug {

    private AntiDebug() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var t = Responses.table(p, q, new String[]{"kind", "name", "addr"});
            var w = new Responses.Window(p);
            for (var sym : program.getSymbolTable().getExternalSymbols()) {
                if (!Hashes.ANTI_DEBUG_APIS.contains(sym.getName())) continue;
                if (!w.take()) continue;
                t.row("IMP", sym.getName(), Responses.addr(sym.getAddress()));
            }
            for (var f : program.getFunctionManager().getFunctions(true)) {
                if (!Hashes.ANTI_DEBUG_APIS.contains(f.getName())) continue;
                if (!w.take()) continue;
                t.row("FN", f.getName(), Responses.addr(f.getEntryPoint()));
            }
            return t.total(w.total()).build();
        });
    }
}
