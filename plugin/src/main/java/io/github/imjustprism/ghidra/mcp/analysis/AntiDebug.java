package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.hashes.Hashes;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.Imports;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class AntiDebug {

    private AntiDebug() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var t = Responses.table(p, q, new String[]{"kind", "name", "addr", "sites"});
            var w = new Responses.Window(p);
            var rm = program.getReferenceManager();
            for (var sym : program.getSymbolTable().getExternalSymbols()) {
                if (!Hashes.ANTI_DEBUG_APIS.contains(sym.getName())) continue;
                if (!w.take()) continue;
                t.row("IMP", sym.getName(), Responses.addr(sym.getAddress()),
                        Imports.callSites(program, sym).size());
            }
            for (var f : program.getFunctionManager().getFunctions(true)) {
                if (!Hashes.ANTI_DEBUG_APIS.contains(f.getName())) continue;
                if (!w.take()) continue;
                int sites = 0;
                for (var ref : rm.getReferencesTo(f.getEntryPoint())) {
                    if (ref.getReferenceType().isCall()) sites++;
                }
                t.row("FN", f.getName(), Responses.addr(f.getEntryPoint()), sites);
            }
            return t.total(w.total()).build();
        });
    }
}
