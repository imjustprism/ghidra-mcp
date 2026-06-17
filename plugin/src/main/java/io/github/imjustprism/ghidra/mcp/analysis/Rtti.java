package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.symbol.SymbolType;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Map;

public final class Rtti {

    private Rtti() {}

    public static String recover(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var st = program.getSymbolTable();
            var rows = new ArrayList<Object[]>();
            long off = p.offset();
            long lim = p.limit();
            long total = 0;
            for (var it = st.getClassNamespaces(); it.hasNext(); ) {
                var cls = it.next();
                var vsyms = st.getSymbols("vftable", cls);
                var vftable = vsyms.isEmpty() ? "" : Responses.addr(vsyms.get(0).getAddress());
                int methods = 0;
                for (var s = st.getSymbols(cls); s.hasNext(); ) {
                    if (s.next().getSymbolType() == SymbolType.FUNCTION) methods++;
                }
                if (total >= off && rows.size() < lim) {
                    rows.add(new Object[]{cls.getName(true), vftable, methods});
                }
                total++;
            }
            var t = Responses.table(p, q, new String[]{"class", "vftable", "methods"});
            for (var r : rows) {
                t.row(r);
            }
            return t.total((int) Math.min(total, Integer.MAX_VALUE)).build();
        });
    }
}
