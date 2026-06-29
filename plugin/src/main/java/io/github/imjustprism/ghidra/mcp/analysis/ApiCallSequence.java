package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class ApiCallSequence {

    private ApiCallSequence() {}

    public static String extract(PluginContext ctx, String addrStr, Map<String, String> q) {
        boolean apiOnly = !"0".equals(q.get("api_only"));
        return ctx.withAddress(addrStr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("no function at or containing " + addrStr);
            var listing = program.getListing();
            var st = program.getSymbolTable();
            var fm = program.getFunctionManager();
            var t = Responses.table(q, new String[]{"i", "addr", "kind", "target"}, 16);
            int idx = 0;
            for (var insn : listing.getInstructions(func.getBody(), true)) {
                for (var ref : insn.getReferencesFrom()) {
                    if (!ref.getReferenceType().isCall()) continue;
                    var to = ref.getToAddress();
                    boolean api = to.isExternalAddress();
                    String name;
                    if (api) {
                        var sym = st.getPrimarySymbol(to);
                        name = sym == null ? to.toString() : sym.getName();
                    } else {
                        var callee = fm.getFunctionAt(to);
                        if (callee != null && callee.isThunk()) {
                            var thunked = callee.getThunkedFunction(true);
                            if (thunked != null && thunked.isExternal()) {
                                api = true;
                                name = thunked.getName();
                            } else {
                                name = callee.getName();
                            }
                        } else {
                            name = callee != null ? callee.getName()
                                    : (fm.getFunctionContaining(to) != null ? fm.getFunctionContaining(to).getName()
                                    : Responses.addr(to));
                        }
                    }
                    if (apiOnly && !api) continue;
                    t.row(idx++, Responses.addr(insn.getAddress()), api ? "api" : "local", name);
                }
            }
            return "# api call sequence of " + func.getName() + " (" + idx + " call(s)"
                    + (apiOnly ? ", api only; api_only=0 for all" : "") + ")\n" + t.total(idx).build();
        });
    }
}
