package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.SymbolType;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Locale;
import java.util.Map;

public final class Rtti {

    private Rtti() {}

    public static String recover(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var st = program.getSymbolTable();
            var classes = new ArrayList<GhidraClass>();
            for (var it = st.getClassNamespaces(); it.hasNext(); ) classes.add(it.next());
            classes.sort(Comparator.comparing((GhidraClass c) -> c.getName(true)));

            int from = Math.min(p.offset(), classes.size());
            int to = (int) Math.min((long) p.offset() + p.limit(), classes.size());
            var t = Responses.table(p, q, new String[]{"class", "vftable", "methods"});
            for (int i = from; i < to; i++) {
                var cls = classes.get(i);
                var vftable = "";
                int methods = 0;
                for (var s = st.getSymbols(cls); s.hasNext(); ) {
                    var sym = s.next();
                    if (sym.getSymbolType() == SymbolType.FUNCTION) {
                        methods++;
                    } else if (vftable.isEmpty() && isVtable(sym.getName())) {
                        vftable = Responses.addr(sym.getAddress());
                    }
                }
                t.row(cls.getName(true), vftable, methods);
            }
            return t.total(classes.size()).build();
        });
    }

    private static boolean isVtable(String name) {
        var lower = name.toLowerCase(Locale.ROOT);
        return lower.contains("vftable") || lower.contains("vtable") || lower.contains("vbtable");
    }
}
