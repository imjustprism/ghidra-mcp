package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.analysis.AntiDebug;
import io.github.imjustprism.ghidra.mcp.analysis.AntiVm;
import io.github.imjustprism.ghidra.mcp.analysis.ApiHashes;
import io.github.imjustprism.ghidra.mcp.analysis.CallGraph;
import io.github.imjustprism.ghidra.mcp.analysis.Cfg;
import io.github.imjustprism.ghidra.mcp.analysis.CfgMetrics;
import io.github.imjustprism.ghidra.mcp.analysis.CfgObfuscation;
import io.github.imjustprism.ghidra.mcp.analysis.CheckFunction;
import io.github.imjustprism.ghidra.mcp.analysis.Completeness;
import io.github.imjustprism.ghidra.mcp.analysis.Constraints;
import io.github.imjustprism.ghidra.mcp.analysis.DecodeStrings;
import io.github.imjustprism.ghidra.mcp.analysis.DynamicApi;
import io.github.imjustprism.ghidra.mcp.analysis.CryptoConstants;
import io.github.imjustprism.ghidra.mcp.analysis.DecompileMinimal;
import io.github.imjustprism.ghidra.mcp.analysis.DominatorTree;
import io.github.imjustprism.ghidra.mcp.analysis.FunctionHash;
import io.github.imjustprism.ghidra.mcp.analysis.Emulator;
import io.github.imjustprism.ghidra.mcp.analysis.EncodedStrings;
import io.github.imjustprism.ghidra.mcp.analysis.Entropy;
import io.github.imjustprism.ghidra.mcp.analysis.IdiomSimplifier;
import io.github.imjustprism.ghidra.mcp.analysis.MagicConstants;
import io.github.imjustprism.ghidra.mcp.analysis.NamespaceGraph;
import io.github.imjustprism.ghidra.mcp.analysis.NeutralizeAntiDebug;
import io.github.imjustprism.ghidra.mcp.analysis.OrphanGaps;
import io.github.imjustprism.ghidra.mcp.analysis.Pcode;
import io.github.imjustprism.ghidra.mcp.analysis.Rtti;
import io.github.imjustprism.ghidra.mcp.analysis.Signatures;
import io.github.imjustprism.ghidra.mcp.analysis.StackStrings;
import io.github.imjustprism.ghidra.mcp.analysis.StructDiagram;
import io.github.imjustprism.ghidra.mcp.analysis.Syscalls;
import io.github.imjustprism.ghidra.mcp.analysis.VTableScan;
import io.github.imjustprism.ghidra.mcp.analysis.XrefGraph;
import io.github.imjustprism.ghidra.mcp.http.Http;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.Demangler;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class AnalysisHandlers {

    private final PluginContext ctx;

    public AnalysisHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    public void register(RouteTable routes) {
        routes.getPage("/find_anti_debug", (p, q) -> AntiDebug.find(ctx, p, q));
        routes.getQuery("/find_encoded_strings", q -> EncodedStrings.find(ctx, q.get("address"),
                Http.parseIntOrDefault(q.get("length"), 0x10000),
                Http.parseIntOrDefault(q.get("min_len"), 6), Page.from(q), q));
        routes.getQuery("/find_api_hashes", q -> ApiHashes.find(ctx, q.get("algo"), Page.from(q), q));
        routes.getQuery("/find_stack_strings", q -> StackStrings.find(ctx, q.get("address"), Page.from(q), q));
        routes.getQuery("/high_entropy_regions", q -> Entropy.highEntropyRegions(ctx,
                Double.parseDouble(q.getOrDefault("threshold", "7.5")),
                Http.parseIntOrDefault(q.get("window"), 256), Page.from(q), q));
        routes.getQuery("/program_info", this::programInfo);
        routes.getQuery("/program_metadata", q -> programMetadata(Page.from(q), q));
        routes.getQuery("/demangle_symbol", q -> Demangler.demangleSymbol(q.get("mangled")));
        routes.getQuery("/pcode_function", q -> Pcode.pcodeFunction(ctx, q.get("address")));
        routes.getQuery("/callgraph_dot", q -> CallGraph.dot(ctx, q.get("address"),
                Http.parseIntOrDefault(q.get("depth"), 2)));
        routes.getQuery("/callgraph", q -> CallGraph.mermaid(ctx, q.get("address"),
                Http.parseIntOrDefault(q.get("depth"), 2), q.get("direction"),
                Http.parseIntOrDefault(q.get("max_nodes"), 0)));
        routes.getQuery("/function_cfg", q -> Cfg.mermaid(ctx, q.get("address")));
        routes.getQuery("/cfg_metrics", q -> CfgMetrics.metrics(ctx, q.get("address"), q));
        routes.getQuery("/dominator_tree", q -> DominatorTree.compute(ctx, q.get("address"), Page.from(q), q));
        routes.getQuery("/xref_graph", q -> XrefGraph.mermaid(ctx, q.get("address"), q.get("max")));
        routes.getQuery("/namespace_graph", q -> NamespaceGraph.mermaid(ctx, q.get("max")));
        routes.getQuery("/struct_diagram", q -> StructDiagram.mermaid(ctx, q.get("filter"),
                Http.parseIntOrDefault(q.get("max"), 0)));
        routes.getQuery("/find_orphan_gaps", q -> OrphanGaps.find(ctx,
                Http.parseIntOrDefault(q.get("min_size"), 16), q));
        routes.getQuery("/vtable_scan", q -> VTableScan.scan(ctx, q));
        routes.postForm("/demangle_all", p -> Demangler.demangleAll(ctx));
        routes.postForm("/emulate", p -> Emulator.emulate(ctx,
                p.get("start"), p.getOrDefault("stop", ""),
                Http.parseIntOrDefault(p.get("max_steps"), 500000),
                p.getOrDefault("skip_calls", ""), p.getOrDefault("capture_addr", ""),
                Http.parseIntOrDefault(p.get("capture_length"), 0),
                Http.parseIntOrDefault(p.get("commit"), 0) != 0));
        routes.getPage("/find_check_function", (p, q) -> CheckFunction.find(ctx, p, q));
        routes.getQuery("/extract_constraints", q -> Constraints.extract(ctx, q.get("address"), q));
        routes.getQuery("/function_completeness", q -> Completeness.single(ctx, q.get("address"), q));
        routes.getQuery("/find_undocumented", q -> Completeness.findUndocumented(ctx, Page.from(q), q));
        routes.getQuery("/find_crypto_constants", q -> CryptoConstants.find(ctx, Page.from(q), q));
        routes.getQuery("/find_syscalls", q -> Syscalls.find(ctx, Page.from(q), q));
        routes.getQuery("/find_anti_vm", q -> AntiVm.find(ctx, Page.from(q), q));
        routes.getQuery("/cfg_obfuscation_score", q -> CfgObfuscation.score(ctx, q.get("address"), q));
        routes.getQuery("/function_hash", q -> FunctionHash.hash(ctx, q.get("address"), q));
        routes.getQuery("/recover_rtti_classes", q -> Rtti.recover(ctx, Page.from(q), q));
        routes.getQuery("/find_dynamic_api_resolution", q -> DynamicApi.find(ctx, Page.from(q), q));
        routes.getQuery("/decode_strings_auto", q -> DecodeStrings.decode(ctx, q.get("address"),
                Http.parseIntOrDefault(q.get("length"), 256),
                Double.parseDouble(q.getOrDefault("min_printable", "0.85")),
                Http.parseIntOrDefault(q.get("max"), 10), q));
        routes.getQuery("/decompile_minimal", q -> DecompileMinimal.run(ctx, q.get("address")));
        routes.getPage("/find_magic_constants", (p, q) -> MagicConstants.find(ctx, p, q));
        routes.postForm("/neutralize_anti_debug", p -> NeutralizeAntiDebug.run(ctx, p));
        routes.postForm("/idiom_simplifier", p -> IdiomSimplifier.run(ctx, p.get("address"), p));
        routes.getQuery("/make_signature", q -> Signatures.make(ctx, q.get("address"),
                Http.parseIntOrDefault(q.get("max_len"), 0), q.getOrDefault("format", "ida")));
        routes.getQuery("/find_signature", q -> Signatures.findSignature(ctx, q.get("pattern"), Page.from(q), q));
        routes.getQuery("/resolve_relative", q -> Signatures.resolveRelative(ctx, q.get("address")));
        routes.getQuery("/find_function_by_string", q -> Signatures.findFunctionByString(ctx,
                q.get("value"), Http.parseIntOrDefault(q.get("max"), 5), q.getOrDefault("format", "ida")));
    }

    public String programMetadata(Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            Map<String, String> md;
            try {
                md = program.getMetadata();
            } catch (Exception e) {
                throw new IllegalStateException("metadata unavailable: " + e.getMessage(), e);
            }
            var t = Responses.table(p, q, new String[]{"key", "value"});
            var w = new Responses.Window(p);
            if (md != null) {
                var keys = new java.util.ArrayList<>(md.keySet());
                java.util.Collections.sort(keys);
                for (var key : keys) {
                    if (!w.take()) continue;
                    var v = md.get(key);
                    t.row(key, v != null ? v : "");
                }
            }
            return t.total(w.total()).build();
        });
    }

    public String programInfo(Map<String, String> q) {
        return ctx.withProgram(program -> {
            var lang = program.getLanguage();
            var desc = lang.getLanguageDescription();
            var t = Responses.table(q, new String[]{"k", "v"}, 10);
            t.row("lang", lang.getLanguageID());
            t.row("proc", lang.getProcessor());
            t.row("bits", desc.getSize());
            t.row("endian", lang.isBigEndian() ? "big" : "little");
            t.row("cspec", program.getCompilerSpec().getCompilerSpecID());
            t.row("image_base", Responses.addr(program.getImageBase()));
            t.row("exe", program.getExecutablePath() != null ? program.getExecutablePath() : "");
            var sha = program.getExecutableSHA256();
            if (sha != null) t.row("sha256", sha);
            var created = program.getCreationDate();
            if (created != null) t.row("created", created.toString());
            try {
                var metadata = program.getMetadata();
                if (metadata != null) {
                    var analyzed = metadata.get("Analyzed");
                    if (analyzed != null) t.row("analyzed", analyzed);
                }
            } catch (Exception e) {
                Msg.trace(AnalysisHandlers.class, "program metadata read", e);
            }
            return t.build();
        });
    }
}
