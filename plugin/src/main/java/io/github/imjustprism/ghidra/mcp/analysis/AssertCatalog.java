package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DecompileCache;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public final class AssertCatalog {

    public static final int DEFAULT_MAX = 40;
    public static final int MAX_FUNCTIONS = 200;

    private static final String[] FAST_COLS = {
            "assert", "fields", "str_addr", "refs", "funcs", "sample", "sample_addr"
    };

    private static final String[] PROVE_COLS = {
            "class", "field", "offset", "width", "base", "container", "confidence",
            "assert", "source", "func", "func_addr"
    };

    private AssertCatalog() {}

    public static String catalog(PluginContext ctx, String filter, boolean prove, int max,
            Page page, Map<String, String> q) {
        return ctx.withProgram(program -> prove
                ? proven(program, filter, max, page, q)
                : fast(program, filter, page, q));
    }

    private static String fast(Program program, String filter, Page page, Map<String, String> q) {
        var hits = NebulaStrings.defined(program, NebulaNames::isThisAssert);
        var t = Responses.table(q, FAST_COLS, Math.min(page.limit(), hits.size()));
        var w = new Responses.Window(page);
        int kept = 0;
        for (var hit : hits) {
            var fields = AssertProofs.fieldsOf(hit.value());
            var fieldJoin = String.join(",", fields);
            if (!NebulaNames.containsIgnoreCase(hit.value(), filter)
                    && !NebulaNames.containsIgnoreCase(fieldJoin, filter)) {
                continue;
            }
            kept++;
            var refs = NebulaStrings.referrers(program, hit.addr());
            var sample = refs.isEmpty() ? "" : refs.get(0).getName();
            var sampleAddr = refs.isEmpty() ? "" : Responses.addr(refs.get(0).getEntryPoint());
            if (!w.take()) continue;
            t.row(hit.value(), fieldJoin, Responses.addr(hit.addr()),
                    refs.size(), refs.size(), sample, sampleAddr);
        }
        var sb = new StringBuilder(256);
        sb.append("# assert_catalog this_asserts=").append(hits.size())
          .append(" shown_filter=").append(kept)
          .append(" prove=false\n");
        sb.append("# no decompile; pass prove=true (and page with offset/max) to run "
                + "prove_offset on each referencing function\n");
        return sb.append(t.total(w.total()).build()).toString();
    }

    private static String proven(Program program, String filter, int max, Page page,
            Map<String, String> q) {
        int cap = max <= 0 ? DEFAULT_MAX : Math.min(max, MAX_FUNCTIONS);
        var hits = NebulaStrings.defined(program, NebulaNames::isThisAssert);
        var seen = new LinkedHashSet<ghidra.program.model.address.Address>();
        var targets = new ArrayList<Function>();
        for (var hit : hits) {
            if (!NebulaNames.containsIgnoreCase(hit.value(), filter)
                    && !matchesFields(hit.value(), filter)) {
                continue;
            }
            for (var fn : NebulaStrings.referrers(program, hit.addr())) {
                if (seen.add(fn.getEntryPoint())) targets.add(fn);
            }
        }
        int skip = Math.max(0, page.offset());
        var proofs = new ArrayList<ProveOffset.Proof>();
        int scanned = 0;
        for (int i = skip; i < targets.size() && scanned < cap; i++) {
            var fn = targets.get(i);
            scanned++;
            String c;
            try {
                c = DecompileCache.decompile(program, fn);
            } catch (RuntimeException e) {
                continue;
            }
            proofs.addAll(ProveOffset.analyze(program, fn, c));
        }
        var t = Responses.table(q, PROVE_COLS, proofs.size());
        int shown = 0;
        for (var p : proofs) {
            if (filter != null && !filter.isBlank()
                    && !NebulaNames.containsIgnoreCase(p.owner(), filter)
                    && !NebulaNames.containsIgnoreCase(p.field(), filter)
                    && !NebulaNames.containsIgnoreCase(p.assertExpr(), filter)) {
                continue;
            }
            shown++;
            t.row(p.owner(), p.field(), p.offset(), p.width(), p.base(), p.container(),
                    p.confidence(), p.assertExpr(), p.source(), p.func(), p.funcAddr());
        }
        var sb = new StringBuilder(256);
        sb.append("# assert_catalog prove=true targets=").append(targets.size())
          .append(" scanned=").append(scanned).append(" from=").append(skip)
          .append(" proofs=").append(proofs.size()).append('\n');
        if (skip + scanned < targets.size()) {
            sb.append("# coverage: ").append(targets.size() - skip - scanned)
              .append(" function(s) not decompiled; re-run with offset=")
              .append(skip + scanned).append('\n');
        }
        return sb.append(t.total(shown).build()).toString();
    }

    private static boolean matchesFields(String expr, String filter) {
        if (filter == null || filter.isBlank()) return true;
        for (var f : AssertProofs.fieldsOf(expr)) {
            if (NebulaNames.containsIgnoreCase(f, filter)) return true;
        }
        return false;
    }
}
