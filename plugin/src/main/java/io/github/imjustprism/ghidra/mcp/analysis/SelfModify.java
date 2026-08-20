package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Functions that both change page protection and write memory — unpacker,
 * hook installer, PE wipe, manual-map.
 */
public final class SelfModify {

    private static final String[] PROTECT = {
            "VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory"
    };
    private static final String[] WRITE = {
            "WriteProcessMemory", "NtWriteVirtualMemory", "RtlMoveMemory", "memcpy", "memmove"
    };

    private SelfModify() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var rows = new ArrayList<String[]>();
            int n = 0;
            for (var f : program.getFunctionManager().getFunctions(true)) {
                if (f.isThunk() || f.isExternal()) continue;
                if (n++ > 6000) break;
                var apis = apiNames(program, f);
                boolean prot = hasAny(apis, PROTECT);
                boolean wr = hasAny(apis, WRITE);
                if (!prot && !wr) continue;
                String kind;
                if (prot && wr) kind = "protect+write";
                else if (prot) kind = "protect";
                else kind = "write";
                if ("write".equals(kind) && !hasAny(apis, new String[]{"WriteProcessMemory", "NtWriteVirtualMemory"})) {
                    continue;
                }
                rows.add(new String[]{kind, f.getName(), Responses.addr(f.getEntryPoint()),
                        String.join(",", apis)});
            }
            var t = Responses.table(p, q, new String[]{"kind", "func", "addr", "apis"});
            var w = new Responses.Window(p);
            for (var r : rows) {
                if (!w.take()) continue;
                t.row((Object[]) r);
            }
            return "# find_self_modify\n" + t.total(w.total()).build();
        });
    }

    static boolean hasAny(List<String> have, String[] want) {
        for (var w : want) if (have.contains(w)) return true;
        return false;
    }

    private static List<String> apiNames(Program program, Function func) {
        var out = new ArrayList<String>();
        var listing = program.getListing();
        var st = program.getSymbolTable();
        var fm = program.getFunctionManager();
        for (var insn : listing.getInstructions(func.getBody(), true)) {
            for (var ref : insn.getReferencesFrom()) {
                if (!ref.getReferenceType().isCall()) continue;
                var to = ref.getToAddress();
                String name = null;
                if (to.isExternalAddress()) {
                    var sym = st.getPrimarySymbol(to);
                    name = sym == null ? null : strip(sym.getName());
                } else {
                    var callee = fm.getFunctionAt(to);
                    if (callee != null && callee.isThunk()) {
                        var th = callee.getThunkedFunction(true);
                        if (th != null) name = strip(th.getName());
                    }
                }
                if (name != null && !out.contains(name)) out.add(name);
            }
        }
        return out;
    }

    private static String strip(String name) {
        if (name.startsWith("__imp_")) return name.substring(6);
        return name;
    }
}
