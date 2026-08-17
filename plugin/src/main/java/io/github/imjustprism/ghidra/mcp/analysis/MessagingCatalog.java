package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class MessagingCatalog {

    private static final String[] COLS = {
            "kind", "class", "fourcc", "fourcc_ascii", "rtti", "func", "func_addr", "refs"
    };

    private MessagingCatalog() {}

    public static String catalog(PluginContext ctx, String filter, Page page, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var byClass = new HashMap<String, FactoryCatalog.Row>();
            for (var r : FactoryCatalog.collect(program)) {
                if (!r.klass().startsWith("Messaging::")) continue;
                var prev = byClass.get(r.klass());
                if (prev == null || ("register".equals(r.via()) && !"register".equals(prev.via()))) {
                    byClass.put(r.klass(), r);
                }
            }
            var rows = new ArrayList<Object[]>();
            for (var hit : NebulaStrings.defined(program, NebulaNames::isMessagingClass)) {
                var fac = byClass.get(hit.value());
                var refs = NebulaStrings.referrers(program, hit.addr());
                var sample = refs.isEmpty() ? "" : refs.get(0).getName();
                var sampleAddr = refs.isEmpty() ? "" : Responses.addr(refs.get(0).getEntryPoint());
                rows.add(new Object[]{
                        "message", hit.value(),
                        fac == null ? "" : fac.fourcc(),
                        fac == null ? "" : fac.fourccAscii(),
                        fac == null ? "" : fac.rtti(),
                        sample, sampleAddr, refs.size()
                });
            }
            var fm = program.getFunctionManager();
            for (var fn : fm.getFunctions(true)) {
                if (fn.isExternal() || fn.isThunk()) continue;
                if (!NebulaNames.isHandleMessageName(fn.getName())) continue;
                rows.add(new Object[]{
                        "handler", handlerOwner(program, fn), "", "", "",
                        fn.getName(), Responses.addr(fn.getEntryPoint()),
                        NebulaStrings.inbound(program, fn)
                });
            }
            var t = Responses.table(q, COLS, Math.min(page.limit(), rows.size()));
            var w = new Responses.Window(page);
            int kept = 0;
            for (var r : rows) {
                if (!NebulaNames.containsIgnoreCase(String.valueOf(r[1]), filter)
                        && !NebulaNames.containsIgnoreCase(String.valueOf(r[5]), filter)
                        && !NebulaNames.containsIgnoreCase(String.valueOf(r[3]), filter)) {
                    continue;
                }
                kept++;
                if (!w.take()) continue;
                t.row(r);
            }
            var sb = new StringBuilder(256);
            sb.append("# messaging_catalog rows=").append(rows.size())
              .append(" shown_filter=").append(kept)
              .append(" factory_joined=").append(byClass.size()).append('\n');
            sb.append("# kind=message is a Messaging:: class string (FourCC/rtti filled "
                    + "when factory_catalog saw the static initializer); kind=handler is "
                    + "a Properties::*::HandleMessage / UI port. Local protocol is the "
                    + "message class; wire opcode is still raknet 0x8b\n");
            return sb.append(t.total(w.total()).build()).toString();
        });
    }

    private static String handlerOwner(Program program, Function fn) {
        for (var s : NebulaStrings.stringsIn(program, fn)) {
            if (s.contains("::HandleMessage(") && NebulaNames.isFuncsig(s)) {
                var owner = AssertProofs.ownerOf(s);
                if (!owner.isEmpty()) return owner;
            }
        }
        return "";
    }
}
