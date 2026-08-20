package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Map;

/**
 * One-call next-gen sample intake: PE facts, capabilities, anti-debug, packer
 * hint, optional hidden-string pass. Run this first on an unknown binary.
 */
public final class SampleIntake {

    private SampleIntake() {}

    public static String run(PluginContext ctx, boolean deep, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> build(ctx, program, deep, p, q));
    }

    private static String build(PluginContext ctx, Program program, boolean deep, Page p,
                                Map<String, String> q) {
        var sb = new StringBuilder(4096);
        sb.append("# sample_intake deep=").append(deep ? "1" : "0").append('\n');

        sb.append("=== pe ===\n");
        try {
            sb.append(PeFacts.facts(ctx, q));
        } catch (RuntimeException e) {
            sb.append("pe facts failed: ").append(e.getMessage()).append('\n');
        }
        if (!sb.toString().endsWith("\n")) sb.append('\n');

        try {
            sb.append("=== packer ===\n").append(UnpackAssist.report(ctx));
            if (!sb.toString().endsWith("\n")) sb.append('\n');
        } catch (RuntimeException e) {
            sb.append("unpack_assist failed: ").append(e.getMessage()).append('\n');
        }

        var caps = CapabilityMap.collect(program);
        var uniq = CapabilityMap.uniqueCaps(caps);
        sb.append("=== capabilities ===\n");
        sb.append("caps\t").append(uniq.isEmpty() ? "(none)" : String.join(",", uniq)).append('\n');
        var ct = Responses.table(p, q, new String[]{"capability", "confidence", "evidence", "where"});
        var cw = new Responses.Window(p);
        for (var h : caps) {
            if (!cw.take()) continue;
            ct.row(h.cap(), h.confidence(), Strings.escapeString(h.evidence()), h.where());
        }
        sb.append(ct.total(cw.total()).build());

        var flags = new LinkedHashSet<String>();
        if (uniq.contains("process_injection")) flags.add("inject");
        if (uniq.contains("c2_http") || uniq.contains("c2_socket")) flags.add("network");
        if (uniq.contains("anti_debug")) flags.add("antidebug");
        if (uniq.contains("license")) flags.add("license");
        if (uniq.contains("crypto_symmetric") || uniq.contains("crypto_hash")) flags.add("crypto");
        if (uniq.contains("hwid")) flags.add("hwid");
        sb.append("flags\t").append(flags.isEmpty() ? "(none)" : String.join(",", flags)).append('\n');

        if (deep) {
            sb.append("=== hidden_strings ===\n");
            try {
                var hits = HiddenStrings.scanProgram(program, "auto", 6);
                var ht = Responses.table(p, q, new String[]{"algo", "func", "value"});
                var hw = new Responses.Window(p);
                for (var h : hits) {
                    if (!hw.take()) continue;
                    ht.row(h.algo(), h.func(), Strings.escapeString(h.value()));
                }
                sb.append(ht.total(hw.total()).build());
            } catch (RuntimeException e) {
                sb.append("hidden strings failed: ").append(e.getMessage()).append('\n');
            }
        } else {
            sb.append("tip\tpass deep=true to also run recover_hidden_strings\n");
        }

        sb.append("next\tcapability_map, recover_auth_surface, recover_crypto_recipe, ");
        sb.append("find_secret_compares, function_behavior on tagged funcs, export_yara\n");
        return sb.toString();
    }
}
