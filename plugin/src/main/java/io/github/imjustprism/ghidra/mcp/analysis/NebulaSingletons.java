package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class NebulaSingletons {

    private static final int MAX_PREVIEW = 500;
    private static final int DEFAULT_MAX = 300;

    private NebulaSingletons() {}

    public static String nameInstances(PluginContext ctx, boolean apply, int max, Map<String, String> q) {
        int cap = max > 0 ? max : DEFAULT_MAX;
        return ctx.withProgram(program -> {
            record Hit(Function function, String oldName, String newName, String signature, int refs, String how) {}
            var hits = new ArrayList<Hit>();
            var claimed = new HashSet<Long>();
            var used = new HashSet<String>();
            var fm = program.getFunctionManager();
            var refMgr = program.getReferenceManager();
            var it = program.getListing().getDefinedData(true);
            while (it.hasNext() && hits.size() < cap) {
                var data = it.next();
                if (data == null || data.getValue() == null) continue;
                var raw = data.getValue().toString();
                if (!raw.contains("::Instance(void)") && !raw.contains("::Instance()")) continue;
                if (!raw.contains("__cdecl") && !raw.contains("__thiscall")) continue;
                var qname = NebulaAssertNamer.qualifiedFromSignature(raw);
                if (qname == null || qname.isBlank()) continue;
                var base = NebulaAssertNamer.sanitize(qname);
                if (base.isBlank()) continue;
                if (!base.toLowerCase(Locale.ROOT).contains("instance")) {
                    base = base + "_Instance";
                }

                var referrers = new ArrayList<Function>();
                var seen = new HashSet<Long>();
                int refs = 0;
                for (var ref : refMgr.getReferencesTo(data.getAddress())) {
                    refs++;
                    var fn = fm.getFunctionContaining(ref.getFromAddress());
                    if (fn == null || fn.isExternal() || fn.isThunk()) continue;
                    if (!seen.add(fn.getEntryPoint().getOffset())) continue;
                    referrers.add(fn);
                }
                var pick = pickInstanceFunction(referrers);
                if (pick == null) continue;
                if (!claimed.add(pick.getEntryPoint().getOffset())) continue;

                if (!used.add(base)) {
                    base = base + "_" + Long.toHexString(pick.getEntryPoint().getOffset() & 0xffff);
                    used.add(base);
                }
                String how = referrers.size() == 1 ? "unique" : "best_of_" + referrers.size();
                hits.add(new Hit(pick, pick.getName(), base, raw, refs, how));
            }

            var statuses = new String[hits.size()];
            java.util.Arrays.fill(statuses, "preview");
            var applied = new int[1];
            if (apply && !hits.isEmpty()) {
                ctx.runOnSwingTx(program, "Name Nebula Instance()", () -> {
                    for (int i = 0; i < hits.size(); i++) {
                        var h = hits.get(i);
                        try {
                            if (!Responses.isAutoName(h.function().getName())
                                    && h.function().getSymbol().getSource() != SourceType.DEFAULT) {
                                statuses[i] = "skipped: already named";
                                continue;
                            }
                            h.function().setName(h.newName(), SourceType.USER_DEFINED);
                            program.getListing().setComment(h.function().getEntryPoint(),
                                    ghidra.program.model.listing.CodeUnit.PLATE_COMMENT,
                                    "singleton Instance() | " + h.signature());
                            statuses[i] = "ok";
                            applied[0]++;
                        } catch (Exception e) {
                            statuses[i] = "failed: " + (e.getMessage() == null
                                    ? e.getClass().getSimpleName() : e.getMessage());
                            Msg.error(ctx.logOwner(), "instance rename failed", e);
                        }
                    }
                    return true;
                });
            }

            var sb = new StringBuilder();
            sb.append(apply
                    ? "# applied " + applied[0] + " of " + hits.size() + " Instance() rename(s)\n"
                    : "# preview name_nebula_instances (pass apply=1) " + hits.size() + "\n");
            sb.append("address\told\tnew\trefs\thow\tstatus\n");
            int shown = Math.min(hits.size(), MAX_PREVIEW);
            for (int i = 0; i < shown; i++) {
                var h = hits.get(i);
                sb.append(Responses.addr(h.function().getEntryPoint())).append('\t')
                        .append(Responses.cell(h.oldName())).append('\t')
                        .append(Responses.cell(h.newName())).append('\t')
                        .append(h.refs()).append('\t')
                        .append(Responses.cell(h.how())).append('\t')
                        .append(Responses.cell(statuses[i])).append('\n');
            }
            if (hits.size() > shown) sb.append("# ").append(hits.size() - shown).append(" more not shown\n");
            if (hits.isEmpty()) {
                sb.append("# no ::Instance(void) sites with an auto-named candidate function\n");
            }
            return sb.toString();
        });
    }

    static Function pickInstanceFunction(List<Function> referrers) {
        if (referrers == null || referrers.isEmpty()) return null;
        var auto = new ArrayList<Function>();
        for (var fn : referrers) {
            if (Responses.isAutoName(fn.getName()) || fn.getSymbol().getSource() == SourceType.DEFAULT) {
                auto.add(fn);
            }
        }
        if (auto.isEmpty()) return null;
        if (auto.size() == 1) return auto.get(0);
        auto.sort(Comparator
                .comparingLong(NebulaSingletons::bodySize)
                .thenComparing(f -> f.getEntryPoint().getOffset()));
        var best = auto.get(0);
        long bestSize = bodySize(best);
        if (bestSize > 0x800) return null;
        int ties = 0;
        for (var fn : auto) {
            if (bodySize(fn) == bestSize) ties++;
        }
        if (ties > 3) return null;
        return best;
    }

    private static long bodySize(Function fn) {
        try {
            return fn.getBody().getNumAddresses();
        } catch (RuntimeException e) {
            return Long.MAX_VALUE;
        }
    }

    public static String listInstances(PluginContext ctx, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var rows = new ArrayList<String[]>();
            var fm = program.getFunctionManager();
            var refMgr = program.getReferenceManager();
            var it = program.getListing().getDefinedData(true);
            while (it.hasNext() && rows.size() < 200) {
                var data = it.next();
                if (data == null || data.getValue() == null) continue;
                var raw = data.getValue().toString();
                if (!raw.contains("::Instance(void)") && !raw.contains("::Instance()")) continue;
                if (!raw.contains("__cdecl") && !raw.contains("__thiscall")) continue;
                var qname = NebulaAssertNamer.qualifiedFromSignature(raw);
                if (qname == null) continue;
                int refs = refMgr.getReferenceCountTo(data.getAddress());
                var referrers = new ArrayList<Function>();
                var seen = new HashSet<Long>();
                int autoN = 0;
                for (var ref : refMgr.getReferencesTo(data.getAddress())) {
                    var fn = fm.getFunctionContaining(ref.getFromAddress());
                    if (fn == null || !seen.add(fn.getEntryPoint().getOffset())) continue;
                    referrers.add(fn);
                    if (Responses.isAutoName(fn.getName())
                            || fn.getSymbol().getSource() == SourceType.DEFAULT) autoN++;
                }
                var pick = pickInstanceFunction(referrers);
                rows.add(new String[]{
                        Responses.addr(data.getAddress()),
                        qname,
                        Integer.toString(refs),
                        Integer.toString(referrers.size()),
                        Integer.toString(autoN),
                        pick == null ? "" : pick.getName(),
                        pick == null ? "" : Responses.addr(pick.getEntryPoint())
                });
            }
            rows.sort((a, b) -> Integer.compare(Integer.parseInt(b[2]), Integer.parseInt(a[2])));
            var t = Responses.table(q, new String[]{
                    "str_addr", "qualified", "refs", "funcs", "auto", "pick", "pick_addr"
            }, rows.size());
            for (var r : rows) t.row((Object[]) r);
            return "# nebula Instance() singletons (from signature strings)\n" + t.total(rows.size()).build();
        });
    }
}
