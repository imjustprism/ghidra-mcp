package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;

public final class AttrCatalog {

    private static final String[] COLS = {
            "name", "kind", "str_addr", "refs", "func", "func_addr"
    };

    private AttrCatalog() {}

    public static String catalog(PluginContext ctx, String filter, Page page, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var rows = new LinkedHashMap<String, Object[]>();
            var register = NebulaStrings.pickHub(program, "Attr::AttributeDefinitionBase::Register");
            var interesting = new LinkedHashSet<Function>();
            if (register != null) {
                for (var wrapper : NebulaStrings.callersOf(program, register)) {
                    interesting.add(wrapper);
                    for (var ctor : NebulaStrings.callersOf(program, wrapper)) {
                        interesting.add(ctor);
                    }
                }
            }
            for (var fn : interesting) {
                for (var s : NebulaStrings.stringsIn(program, fn)) {
                    if (NebulaNames.isMoneyAttr(s) || NebulaNames.isAttrName(s)) {
                        addHit(rows, s, kindOf(s), null, fn, 0);
                    }
                }
            }
            for (var hit : NebulaStrings.defined(program, NebulaNames::isMoneyAttr)) {
                var refs = NebulaStrings.referrers(program, hit.addr());
                var fn = refs.isEmpty() ? null : refs.get(0);
                addHit(rows, hit.value(), kindOf(hit.value()), hit, fn, refs.size());
            }
            var t = Responses.table(q, COLS, Math.min(page.limit(), rows.size()));
            var w = new Responses.Window(page);
            int kept = 0;
            for (var r : rows.values()) {
                if (!NebulaNames.containsIgnoreCase(String.valueOf(r[0]), filter)
                        && !NebulaNames.containsIgnoreCase(String.valueOf(r[1]), filter)) {
                    continue;
                }
                kept++;
                if (!w.take()) continue;
                t.row(r);
            }
            var sb = new StringBuilder(256);
            sb.append("# attr_catalog names=").append(rows.size())
              .append(" shown_filter=").append(kept)
              .append(" register=").append(register == null ? "" : register.getName())
              .append('\n');
            sb.append("# economy is Attr names (money_rc=gold, money_vc=premium), not a "
                    + "C++ field; prove_offset field=gold will be empty on purpose\n");
            return sb.append(t.total(w.total()).build()).toString();
        });
    }

    private static void addHit(Map<String, Object[]> rows, String name, String kind,
            NebulaStrings.Hit hit, Function fn, int refs) {
        var next = new Object[]{
                name, kind,
                hit == null ? "" : Responses.addr(hit.addr()),
                refs,
                fn == null ? "" : fn.getName(),
                fn == null ? "" : Responses.addr(fn.getEntryPoint())
        };
        var prev = rows.get(name);
        if (prev == null) {
            rows.put(name, next);
            return;
        }
        if (String.valueOf(prev[2]).isEmpty() && hit != null) rows.put(name, next);
    }

    private static String kindOf(String name) {
        if (NebulaNames.isMoneyAttr(name)) return "money";
        if (name.startsWith("gold") || name.contains("gold")) return "money";
        return "attr";
    }
}
