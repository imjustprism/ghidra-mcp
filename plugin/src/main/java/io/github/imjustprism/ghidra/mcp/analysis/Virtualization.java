package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

public final class Virtualization {

    private static final int SITE_CAP = 500;

    private Virtualization() {}

    public static String analyze(PluginContext ctx, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var blocks = Protector.protectedBlocks(program);
            if (blocks.isEmpty()) {
                return "# no protector/packed sections detected; nothing to analyze\n";
            }
            var set = new AddressSet();
            var head = new StringBuilder("# virtualization / protector boundary analysis\n");
            for (var b : blocks) {
                set.addRange(b.getStart(), b.getEnd());
                head.append("# protected: ").append(b.getName()).append(' ').append(Protector.perms(b))
                        .append(" entropy ").append("%.2f".formatted(Entropy.blockEntropy(b)))
                        .append(" -> ").append(Protector.classify(b)).append('\n');
            }
            var rm = program.getReferenceManager();
            return head + entries(program, rm, set, q) + exits(program, rm, set, q);
        });
    }

    private static final class Entry {
        int hits;
        final TreeSet<String> srcFns = new TreeSet<>();
        final TreeSet<String> kinds = new TreeSet<>();
    }

    private static String entries(Program program, ReferenceManager rm, AddressSetView set,
                                  Map<String, String> q) {
        var byTarget = new LinkedHashMap<Address, Entry>();
        var sites = Responses.table(q, new String[]{"from", "function", "to", "type"}, 16);
        int siteCount = 0;
        boolean capped = false;
        var fm = program.getFunctionManager();
        for (var dest : rm.getReferenceDestinationIterator(set, true)) {
            for (var ref : rm.getReferencesTo(dest)) {
                var from = ref.getFromAddress();
                if (set.contains(from)) continue;
                var e = byTarget.computeIfAbsent(dest, k -> new Entry());
                e.hits++;
                var fn = fm.getFunctionContaining(from);
                var fnName = fn == null ? "" : fn.getName();
                if (!fnName.isEmpty()) e.srcFns.add(fnName);
                e.kinds.add(ref.getReferenceType().getName());
                if (siteCount < SITE_CAP) {
                    sites.row(Responses.addr(from), fnName, Responses.addr(dest),
                            ref.getReferenceType().getName());
                    siteCount++;
                } else {
                    capped = true;
                }
            }
        }
        var grouped = Responses.table(q, new String[]{"engine_target", "hits", "src_functions", "kinds"}, 8);
        for (var en : byTarget.entrySet()) {
            var e = en.getValue();
            grouped.row(Responses.addr(en.getKey()), e.hits, e.srcFns.size(), String.join("|", e.kinds));
        }
        return "=== engine entry points (normal code -> protected) ===\n"
                + grouped.total(byTarget.size()).build()
                + "=== entry sites" + (capped ? " (capped at " + SITE_CAP + ")" : "") + " ===\n"
                + sites.total(siteCount).build();
    }

    private static String exits(Program program, ReferenceManager rm, AddressSetView set,
                                Map<String, String> q) {
        var mem = program.getMemory();
        var byTarget = new LinkedHashMap<Address, int[]>();
        for (var src : rm.getReferenceSourceIterator(set, true)) {
            for (var ref : rm.getReferencesFrom(src)) {
                var to = ref.getToAddress();
                if (set.contains(to)) continue;
                var rt = ref.getReferenceType();
                boolean realCode = to.isMemoryAddress() && mem.contains(to) && (rt.isCall() || rt.isJump());
                if (!realCode && !to.isExternalAddress()) continue;
                byTarget.computeIfAbsent(to, k -> new int[1])[0]++;
            }
        }
        var st = program.getSymbolTable();
        var t = Responses.table(q, new String[]{"to", "symbol", "hits"}, 8);
        for (var en : byTarget.entrySet()) {
            var sym = st.getPrimarySymbol(en.getKey());
            t.row(Responses.addr(en.getKey()), sym == null ? "" : sym.getName(), en.getValue()[0]);
        }
        var note = byTarget.isEmpty()
                ? "# none resolved statically — a packed/virtualized engine resolves outbound calls at"
                    + " runtime; use live_attach / debugger to capture them\n"
                : "";
        return "=== protected -> normal (resolved calls/jumps the engine reaches) ===\n"
                + note + t.total(byTarget.size()).build();
    }
}
