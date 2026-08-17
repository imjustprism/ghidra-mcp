package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;

public final class SourceTree {

    private static final String[] COLS = {
            "path", "dir", "strings", "xrefs", "funcs", "sample", "sample_addr"
    };

    private SourceTree() {}

    public static String catalog(PluginContext ctx, String filter, Page page, Map<String, String> q) {
        return ctx.withProgram(program -> {
            record Acc(int strings, int xrefs, int funcs, String sample, String sampleAddr) {}
            var acc = new LinkedHashMap<String, Acc>();
            for (var hit : NebulaStrings.defined(program, NebulaNames::looksLikeSourcePath)) {
                var path = AssertProofs.normalizePath(hit.value());
                if (path.isEmpty()) continue;
                var refs = NebulaStrings.referrers(program, hit.addr());
                var sample = refs.isEmpty() ? "" : refs.get(0).getName();
                var sampleAddr = refs.isEmpty() ? "" : Responses.addr(refs.get(0).getEntryPoint());
                acc.merge(path, new Acc(1, refs.size(), refs.size(), sample, sampleAddr),
                        (a, b) -> new Acc(a.strings + b.strings, a.xrefs + b.xrefs,
                                a.funcs + b.funcs,
                                a.sample.isEmpty() ? b.sample : a.sample,
                                a.sampleAddr.isEmpty() ? b.sampleAddr : a.sampleAddr));
            }
            var paths = new ArrayList<>(acc.keySet());
            paths.sort(Comparator.naturalOrder());
            var t = Responses.table(q, COLS, Math.min(page.limit(), paths.size()));
            var w = new Responses.Window(page);
            int kept = 0;
            for (var path : paths) {
                if (!NebulaNames.containsIgnoreCase(path, filter)) continue;
                kept++;
                if (!w.take()) continue;
                var a = acc.get(path);
                t.row(path, dirOf(path), a.strings, a.xrefs, a.funcs, a.sample, a.sampleAddr);
            }
            var sb = new StringBuilder(256);
            sb.append("# source_tree files=").append(acc.size())
              .append(" shown_filter=").append(kept).append('\n');
            sb.append("# paths are stripped at /code/, /nebula3/, /drasa_online/; "
                    + "filter=shared/skills or client/properties to open a subsystem\n");
            return sb.append(t.total(w.total()).build()).toString();
        });
    }

    static String dirOf(String path) {
        int slash = path.replace('\\', '/').lastIndexOf('/');
        return slash < 0 ? "" : path.substring(0, slash);
    }
}
