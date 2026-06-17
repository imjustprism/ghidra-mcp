package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class DynamicApi {

    private static final List<String> RESOLVERS = List.of(
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetModuleHandleA", "GetModuleHandleW", "LdrGetProcedureAddress", "LdrLoadDll", "dlsym", "dlopen"
    );

    private DynamicApi() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var st = program.getSymbolTable();
            var refs = program.getReferenceManager();
            var fm = program.getFunctionManager();
            var rows = new ArrayList<Object[]>();
            long off = p.offset();
            long lim = p.limit();
            long total = 0;
            for (var name : RESOLVERS) {
                for (var sym : st.getSymbols(name)) {
                    var it = refs.getReferencesTo(sym.getAddress());
                    while (it.hasNext()) {
                        var from = it.next().getFromAddress();
                        if (!from.isMemoryAddress()) continue;
                        var fn = fm.getFunctionContaining(from);
                        if (total >= off && rows.size() < lim) {
                            rows.add(new Object[]{Responses.addr(from), fn != null ? fn.getName() : "", name});
                        }
                        total++;
                    }
                }
            }
            var t = Responses.table(p, q, new String[]{"site", "caller", "resolver"});
            for (var r : rows) {
                t.row(r);
            }
            return t.total((int) Math.min(total, Integer.MAX_VALUE)).build();
        });
    }
}
