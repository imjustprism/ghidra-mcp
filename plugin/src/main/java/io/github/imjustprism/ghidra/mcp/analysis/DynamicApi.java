package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

public final class DynamicApi {

    private static final List<String> RESOLVERS = List.of(
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetModuleHandleA", "GetModuleHandleW", "LdrGetProcedureAddress", "LdrLoadDll", "dlsym", "dlopen"
    );

    private static final List<String> PREFIXES = List.of("", "_", "__imp_");

    private DynamicApi() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var st = program.getSymbolTable();
            var refs = program.getReferenceManager();
            var fm = program.getFunctionManager();
            var seen = new HashSet<Address>();
            var rows = new ArrayList<Object[]>();
            long off = p.offset();
            long lim = p.limit();
            long total = 0;
            for (var base : RESOLVERS) {
                for (var prefix : PREFIXES) {
                    for (var sym : st.getSymbols(prefix + base)) {
                        var it = refs.getReferencesTo(sym.getAddress());
                        while (it.hasNext()) {
                            var r = it.next();
                            if (!r.getReferenceType().isCall()) continue;
                            var from = r.getFromAddress();
                            if (!from.isMemoryAddress() || !seen.add(from)) continue;
                            var fn = fm.getFunctionContaining(from);
                            if (total >= off && rows.size() < lim) {
                                rows.add(new Object[]{Responses.addr(from), fn != null ? fn.getName() : "", base});
                            }
                            total++;
                        }
                    }
                }
            }
            var t = Responses.table(p, q, new String[]{"site", "caller", "resolver"});
            for (var row : rows) {
                t.row(row);
            }
            return t.total((int) Math.min(total, Integer.MAX_VALUE)).build();
        });
    }
}
