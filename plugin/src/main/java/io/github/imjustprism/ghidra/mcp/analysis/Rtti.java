package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Locale;
import java.util.Map;

public final class Rtti {

    private static final int MAX_VTABLE_SLOTS = 4096;

    private Rtti() {}

    public static String recover(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var st = program.getSymbolTable();
            var classes = new ArrayList<ClassInfo>();
            for (var it = st.getClassNamespaces(); it.hasNext(); ) {
                var c = it.next();
                if (!isRealClass(c.getName(false))) continue;
                Address vftableAddr = null;
                int methods = 0;
                for (var s = st.getSymbols(c); s.hasNext(); ) {
                    Symbol sym = s.next();
                    if (sym.getSymbolType() == SymbolType.FUNCTION) {
                        methods++;
                    } else if (vftableAddr == null && isVtable(sym.getName())) {
                        vftableAddr = sym.getAddress();
                    }
                }
                if (methods == 0 && vftableAddr != null) {
                    methods = countVtableEntries(program, vftableAddr);
                }
                classes.add(new ClassInfo(c.getName(true), vftableAddr, methods));
            }
            classes.sort(Comparator.comparing((ClassInfo c) -> c.vftable() == null)
                    .thenComparing(Comparator.comparingInt(ClassInfo::methods).reversed())
                    .thenComparing(ClassInfo::name));

            int from = Math.min(p.offset(), classes.size());
            int to = (int) Math.min((long) p.offset() + p.limit(), classes.size());
            var t = Responses.table(p, q, new String[]{"class", "vftable", "methods"});
            for (int i = from; i < to; i++) {
                var ci = classes.get(i);
                t.row(ci.name(), ci.vftable() == null ? "" : Responses.addr(ci.vftable()), ci.methods());
            }
            return t.total(classes.size()).build();
        });
    }

    private record ClassInfo(String name, Address vftable, int methods) {}

    private static int countVtableEntries(Program program, Address vt) {
        Memory mem = program.getMemory();
        int ptrSize = program.getDefaultPointerSize();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        int count = 0;
        try {
            Address cur = vt;
            for (int i = 0; i < MAX_VTABLE_SLOTS; i++) {
                long val = ptrSize == 8 ? mem.getLong(cur) : mem.getInt(cur) & 0xffffffffL;
                if (val == 0) break;
                Address target = space.getAddress(val);
                var block = mem.getBlock(target);
                if (block == null || !block.isExecute()) break;
                count++;
                cur = cur.add(ptrSize);
            }
        } catch (Exception ignored) {
        }
        return count;
    }

    private static boolean isRealClass(String leaf) {
        if (leaf == null || leaf.isBlank()) return false;
        char c = leaf.charAt(0);
        return Character.isLetter(c) || c == '_' || c == '<';
    }

    private static boolean isVtable(String name) {
        var lower = name.toLowerCase(Locale.ROOT);
        return lower.contains("vftable") || lower.contains("vtable");
    }
}
