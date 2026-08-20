package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.analysis.AuthSurface;
import io.github.imjustprism.ghidra.mcp.analysis.AntiDebug;
import io.github.imjustprism.ghidra.mcp.analysis.CapabilityMap;
import io.github.imjustprism.ghidra.mcp.analysis.ApiCallSequence;
import io.github.imjustprism.ghidra.mcp.analysis.Assemble;
import io.github.imjustprism.ghidra.mcp.analysis.AntiVm;
import io.github.imjustprism.ghidra.mcp.analysis.ApiHashes;
import io.github.imjustprism.ghidra.mcp.analysis.CallGraph;
import io.github.imjustprism.ghidra.mcp.analysis.Cfg;
import io.github.imjustprism.ghidra.mcp.analysis.CfgMetrics;
import io.github.imjustprism.ghidra.mcp.analysis.CfgObfuscation;
import io.github.imjustprism.ghidra.mcp.analysis.CheckFunction;
import io.github.imjustprism.ghidra.mcp.analysis.Completeness;
import io.github.imjustprism.ghidra.mcp.analysis.Constraints;
import io.github.imjustprism.ghidra.mcp.analysis.Coverage;
import io.github.imjustprism.ghidra.mcp.analysis.Diff;
import io.github.imjustprism.ghidra.mcp.analysis.DecodeKeystream;
import io.github.imjustprism.ghidra.mcp.analysis.DecodeStrings;
import io.github.imjustprism.ghidra.mcp.analysis.DynamicApi;
import io.github.imjustprism.ghidra.mcp.analysis.CryptoConstants;
import io.github.imjustprism.ghidra.mcp.analysis.CryptoRecipe;
import io.github.imjustprism.ghidra.mcp.analysis.DominatorTree;
import io.github.imjustprism.ghidra.mcp.analysis.FunctionHash;
import io.github.imjustprism.ghidra.mcp.analysis.Emulator;
import io.github.imjustprism.ghidra.mcp.analysis.EncodedStrings;
import io.github.imjustprism.ghidra.mcp.analysis.ExtractIocs;
import io.github.imjustprism.ghidra.mcp.analysis.FormatStringVulns;
import io.github.imjustprism.ghidra.mcp.analysis.FunctionBehavior;
import io.github.imjustprism.ghidra.mcp.analysis.HashBlobs;
import io.github.imjustprism.ghidra.mcp.analysis.HiddenStrings;
import io.github.imjustprism.ghidra.mcp.analysis.IocExport;
import io.github.imjustprism.ghidra.mcp.analysis.PeFacts;
import io.github.imjustprism.ghidra.mcp.analysis.SampleIntake;
import io.github.imjustprism.ghidra.mcp.analysis.SdkExport;
import io.github.imjustprism.ghidra.mcp.analysis.SecretCompares;
import io.github.imjustprism.ghidra.mcp.analysis.SelfModify;
import io.github.imjustprism.ghidra.mcp.analysis.Entropy;
import io.github.imjustprism.ghidra.mcp.analysis.IdiomSimplifier;
import io.github.imjustprism.ghidra.mcp.analysis.MagicConstants;
import io.github.imjustprism.ghidra.mcp.analysis.NamespaceGraph;
import io.github.imjustprism.ghidra.mcp.analysis.NeutralizeAntiDebug;
import io.github.imjustprism.ghidra.mcp.analysis.Obfuscation;
import io.github.imjustprism.ghidra.mcp.analysis.OrphanGaps;
import io.github.imjustprism.ghidra.mcp.analysis.Pcode;
import io.github.imjustprism.ghidra.mcp.analysis.PointerScan;
import io.github.imjustprism.ghidra.mcp.analysis.Protector;
import io.github.imjustprism.ghidra.mcp.analysis.RopGadgets;
import io.github.imjustprism.ghidra.mcp.analysis.Rtti;
import io.github.imjustprism.ghidra.mcp.analysis.SecurityMitigations;
import io.github.imjustprism.ghidra.mcp.analysis.Scripts;
import io.github.imjustprism.ghidra.mcp.analysis.Signatures;
import io.github.imjustprism.ghidra.mcp.analysis.StackStrings;
import io.github.imjustprism.ghidra.mcp.analysis.StructDiagram;
import io.github.imjustprism.ghidra.mcp.analysis.Syscalls;
import io.github.imjustprism.ghidra.mcp.analysis.CodeContext;
import io.github.imjustprism.ghidra.mcp.analysis.NebulaAssertNamer;
import io.github.imjustprism.ghidra.mcp.analysis.NebulaBootstrap;
import io.github.imjustprism.ghidra.mcp.analysis.NebulaClassGraph;
import io.github.imjustprism.ghidra.mcp.analysis.NebulaContainers;
import io.github.imjustprism.ghidra.mcp.analysis.NebulaShapes;
import io.github.imjustprism.ghidra.mcp.analysis.NebulaSingletons;
import io.github.imjustprism.ghidra.mcp.analysis.ProveOffset;
import io.github.imjustprism.ghidra.mcp.analysis.Reachability;
import io.github.imjustprism.ghidra.mcp.analysis.SourceTree;
import io.github.imjustprism.ghidra.mcp.analysis.TlsSingletons;
import io.github.imjustprism.ghidra.mcp.analysis.FactoryCatalog;
import io.github.imjustprism.ghidra.mcp.analysis.AssertCatalog;
import io.github.imjustprism.ghidra.mcp.analysis.MessagingCatalog;
import io.github.imjustprism.ghidra.mcp.analysis.AttrCatalog;
import io.github.imjustprism.ghidra.mcp.analysis.FuncsigGraph;
import io.github.imjustprism.ghidra.mcp.analysis.TlsCallbacks;
import io.github.imjustprism.ghidra.mcp.analysis.TlsSingletonMap;
import io.github.imjustprism.ghidra.mcp.util.Live;
import io.github.imjustprism.ghidra.mcp.util.ProcessMemory;
import io.github.imjustprism.ghidra.mcp.analysis.Taint;
import io.github.imjustprism.ghidra.mcp.analysis.UnpackAssist;
import io.github.imjustprism.ghidra.mcp.analysis.Virtualization;
import io.github.imjustprism.ghidra.mcp.analysis.VmDescriptor;
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
        routes.getQuery("/recover_hidden_strings", q -> HiddenStrings.recover(ctx, q.get("address"),
                q.get("algo"), Http.parseIntOrDefault(q.get("min_len"), 4),
                Http.parseBool(q.get("apply"), false), Page.from(q), q));
        routes.getQuery("/recover_auth_surface", q -> AuthSurface.recover(ctx, Page.from(q), q));
        routes.getQuery("/function_behavior", q -> FunctionBehavior.summarize(ctx, q.get("address"),
                Page.from(q), q));
        routes.getQuery("/sample_intake", q -> SampleIntake.run(ctx, Http.parseBool(q.get("deep"), false),
                Page.from(q), q));
        routes.getQuery("/capability_map", q -> CapabilityMap.map(ctx, Page.from(q), q));
        routes.getQuery("/recover_crypto_recipe", q -> CryptoRecipe.recover(ctx, q.get("address"),
                Page.from(q), q));
        routes.getQuery("/find_secret_compares", q -> SecretCompares.find(ctx, Page.from(q), q));
        routes.getQuery("/export_yara", q -> IocExport.export(ctx, q.get("format"), q.get("name"),
                Http.parseBool(q.get("deep"), false), Page.from(q), q));
        routes.getQuery("/decode_keystream", q -> DecodeKeystream.decode(ctx, q.get("address"),
                Http.parseIntOrDefault(q.get("length"), 64), q.get("seed"), q.get("algo"),
                Http.parseIntOrDefault(q.get("increment"), 1), q));
        routes.getQuery("/pe_facts", q -> PeFacts.facts(ctx, q));
        routes.getQuery("/find_hash_blobs", q -> HashBlobs.find(ctx, Page.from(q), q));
        routes.getQuery("/find_self_modify", q -> SelfModify.find(ctx, Page.from(q), q));
        routes.getQuery("/find_api_hashes", q -> ApiHashes.find(ctx, q.get("algo"), Page.from(q), q));
        routes.getQuery("/find_stack_strings", q -> StackStrings.find(ctx, q.get("address"), Page.from(q), q));
        routes.getQuery("/high_entropy_regions", q -> Entropy.highEntropyRegions(ctx,
                Double.parseDouble(q.getOrDefault("threshold", "7.5")),
                Http.parseIntOrDefault(q.get("window"), 256), Page.from(q), q));
        routes.getQuery("/detect_protector", q -> Protector.detect(ctx, q));
        routes.getQuery("/analyze_virtualization", q -> Virtualization.analyze(ctx, q));
        routes.getQuery("/obfuscation_profile", q -> Obfuscation.profile(ctx, q));
        routes.getQuery("/detect_security_mitigations", q -> SecurityMitigations.detect(ctx, q));
        routes.getQuery("/list_tls_callbacks", q -> TlsCallbacks.list(ctx, q));
        routes.getQuery("/tls_singleton_map", q -> {
            Integer pid = null;
            try {
                if (Live.attached()) pid = Live.pid();
            } catch (RuntimeException ignored) {
            }
            return TlsSingletonMap.map(ctx, q, new ProcessMemory(), pid);
        });
        routes.getQuery("/nebula_container_layout", q -> NebulaContainers.layout(ctx, q.get("address"),
                q.get("variable"), q));
        routes.getQuery("/prove_offset", q -> ProveOffset.prove(ctx, q.get("address"), q.get("field"),
                q.get("class"), Http.parseBool(q.get("proven_only"), false),
                Http.parseIntOrDefault(q.get("max"), ProveOffset.DEFAULT_MAX), Page.from(q), q));
        routes.getQuery("/address_context", q -> CodeContext.context(ctx, q.get("address"),
                Http.parseIntOrDefault(q.get("count"), CodeContext.DEFAULT_COUNT),
                Http.parseIntOrDefault(q.get("bytes"), CodeContext.DEFAULT_BYTES), q));
        routes.getQuery("/reachability", q -> Reachability.analyze(ctx, q.get("target"),
                Http.parseIntOrDefault(q.get("depth"), Reachability.DEFAULT_DEPTH),
                Http.parseIntOrDefault(q.get("max"), Reachability.DEFAULT_MAX), q));
        routes.getQuery("/nebula_shape", q -> NebulaShapes.shapes(ctx, q.get("address"),
                q.get("kind"), q));
        routes.getQuery("/derive_tls_singletons", q -> TlsSingletons.derive(ctx, q.get("class"),
                Http.parseIntOrDefault(q.get("max"), TlsSingletons.DEFAULT_MAX),
                Http.parseBool(q.get("apply"), false), Page.from(q), q));
        routes.getQuery("/factory_catalog", q -> FactoryCatalog.catalog(ctx, q.get("filter"),
                Page.from(q), q));
        routes.getQuery("/nebula_class_graph", q -> NebulaClassGraph.graph(ctx, q.get("filter"),
                q.get("root"), q.get("ctor"), Page.from(q), q));
        routes.getQuery("/sdk_export", q -> SdkExport.export(ctx, q.get("filter"),
                Page.from(q), q));
        routes.getQuery("/assert_catalog", q -> AssertCatalog.catalog(ctx, q.get("filter"),
                Http.parseBool(q.get("prove"), false),
                Http.parseIntOrDefault(q.get("max"), AssertCatalog.DEFAULT_MAX), Page.from(q), q));
        routes.getQuery("/messaging_catalog", q -> MessagingCatalog.catalog(ctx, q.get("filter"),
                Page.from(q), q));
        routes.getQuery("/attr_catalog", q -> AttrCatalog.catalog(ctx, q.get("filter"),
                Page.from(q), q));
        routes.getQuery("/source_tree", q -> SourceTree.catalog(ctx, q.get("filter"),
                Page.from(q), q));
        routes.getQuery("/funcsig_graph", q -> FuncsigGraph.graph(ctx, q.get("filter"),
                q.get("fmt"), q.get("max"), Page.from(q), q));
        routes.getQuery("/nebula_assert_helpers", q -> NebulaAssertNamer.findHelpers(ctx, q));
        routes.getQuery("/nebula_engine_survey", q -> NebulaAssertNamer.survey(ctx, q));
        routes.postForm("/nebula_bootstrap", p -> NebulaBootstrap.dispatch(ctx, p));
        routes.postForm("/seed_nebula_helpers", p -> NebulaAssertNamer.seedHelpers(ctx,
                Http.parseBool(p.get("apply"), false), p));
        routes.postForm("/name_from_n_assert", p -> NebulaAssertNamer.name(ctx, p.get("address"),
                Http.parseBool(p.get("apply"), false),
                Http.parseIntOrDefault(p.get("max"), 200),
                p.getOrDefault("mode", "auto"), p));
        routes.postForm("/name_from_signatures", p -> NebulaAssertNamer.nameFromSignatures(ctx,
                p.get("address"), Http.parseBool(p.get("apply"), false),
                Http.parseIntOrDefault(p.get("max"), 500), p));
        routes.getQuery("/list_nebula_instances", q -> NebulaSingletons.listInstances(ctx, q));
        routes.postForm("/name_nebula_instances", p -> NebulaSingletons.nameInstances(ctx,
                Http.parseBool(p.get("apply"), false),
                Http.parseIntOrDefault(p.get("max"), 300), p));
        routes.getQuery("/assemble_code", q -> Assemble.assemble(ctx, q.get("address"), q.get("assembly")));
        routes.getQuery("/extract_api_call_sequences", q -> ApiCallSequence.extract(ctx, q.get("address"), q));
        routes.getPage("/extract_iocs", (p, q) -> ExtractIocs.find(ctx, p, q));
        routes.getPage("/find_rop_gadgets", (p, q) -> RopGadgets.find(ctx, q.get("filter"),
                Http.parseIntOrDefault(q.get("max_instrs"), 5), p, q));
        routes.getPage("/find_format_string_vulns", (p, q) -> FormatStringVulns.find(ctx, p, q));
        routes.getQuery("/vm_descriptor_table", q -> VmDescriptor.parse(ctx, q.get("table_address"),
                Http.parseIntOrDefault(q.get("max_entries"), 256), q));
        routes.getQuery("/program_info", this::programInfo);
        routes.getQuery("/program_metadata", q -> programMetadata(Page.from(q), q));
        routes.getQuery("/demangle_symbol", q -> Demangler.demangleSymbol(q.get("mangled")));
        routes.getQuery("/pcode_function", q -> Pcode.pcodeFunction(ctx, q.get("address")));
        routes.getQuery("/callgraph", q -> "dot".equalsIgnoreCase(q.get("format"))
                ? CallGraph.dot(ctx, q.get("address"), Http.parseIntOrDefault(q.get("depth"), 2))
                : CallGraph.mermaid(ctx, q.get("address"),
                Http.parseIntOrDefault(q.get("depth"), 2), q.get("direction"),
                Http.parseIntOrDefault(q.get("max_nodes"), 0)));
        routes.getQuery("/function_cfg", q -> Cfg.mermaid(ctx, q.get("address")));
        routes.getQuery("/cfg_metrics", q -> CfgMetrics.metrics(ctx, q.get("address"), q));
        routes.getQuery("/dominator_tree", q -> DominatorTree.compute(ctx, q.get("address"), Page.from(q), q));
        routes.getQuery("/xref_graph", q -> "html".equalsIgnoreCase(q.get("fmt"))
                ? XrefGraph.html(ctx, q.get("address"), q.get("max"))
                : XrefGraph.mermaid(ctx, q.get("address"), q.get("max")));
        routes.getQuery("/namespace_graph", q -> "funcsig".equalsIgnoreCase(q.get("source"))
                ? FuncsigGraph.graph(ctx, q.get("filter"), q.getOrDefault("fmt", "mermaid"),
                        q.get("max"), Page.from(q), q)
                : NamespaceGraph.mermaid(ctx, q.get("max")));
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
        routes.postForm("/emulate_function", p -> Emulator.emulateFunction(ctx,
                p.get("function_address"), p.getOrDefault("args", ""),
                Http.parseIntOrDefault(p.get("max_steps"), 200000),
                p.getOrDefault("capture_addr", ""), Http.parseIntOrDefault(p.get("capture_length"), 0)));
        routes.postForm("/recover_decoded_strings", p -> Emulator.recoverDecodedStrings(ctx,
                p.get("function_address"), p.getOrDefault("args", ""),
                Http.parseIntOrDefault(p.get("min_len"), 4),
                Http.parseIntOrDefault(p.get("max_steps"), 200000),
                p.getOrDefault("output_addr", ""), Http.parseIntOrDefault(p.get("output_length"), 4096), p));
        routes.getPage("/find_check_function", (p, q) -> CheckFunction.find(ctx, p, q));
        routes.getQuery("/extract_constraints", q -> Constraints.extract(ctx, q.get("address"), q));
        routes.getQuery("/simplify_expression",
                q -> io.github.imjustprism.ghidra.mcp.analysis.mba.MbaSimplify.run(ctx, q.get("address"), q));
        routes.getQuery("/find_opaque_predicates",
                q -> io.github.imjustprism.ghidra.mcp.analysis.mba.FindOpaque.run(ctx, q.get("address"), q));
        routes.getQuery("/function_completeness", q -> Completeness.single(ctx, q.get("address"), q));
        routes.getQuery("/find_undocumented", q -> Completeness.findUndocumented(ctx, Page.from(q), q));
        routes.getQuery("/find_crypto_constants", q -> CryptoConstants.find(ctx, Page.from(q), q));
        routes.getQuery("/find_syscalls", q -> Syscalls.find(ctx, Page.from(q), q));
        routes.getQuery("/find_anti_vm", q -> AntiVm.find(ctx, Page.from(q), q));
        routes.getQuery("/cfg_obfuscation_score", q -> CfgObfuscation.score(ctx, q.get("address"), q));
        routes.getQuery("/unpack_assist", q -> UnpackAssist.report(ctx));
        routes.getPage("/coverage", (p, q) -> switch (q.getOrDefault("op", "report")) {
            case "diff" -> Coverage.diff(ctx, q.get("path_a"), q.get("path_b"), p, q);
            case "from_trace" -> Coverage.traceToCoverage(ctx, q.get("path"), p, q);
            default -> Coverage.report(ctx, q.get("path"), p, q);
        });
        routes.getPage("/taint_forward", (p, q) -> Taint.slice(ctx, q.get("address"), true, p, q));
        routes.getPage("/taint_backward", (p, q) -> Taint.slice(ctx, q.get("address"), false, p, q));
        routes.getQuery("/diff_functions", q -> {
            var mode = q.getOrDefault("mode", "structural");
            if ("semantic".equalsIgnoreCase(mode)) {
                return Emulator.semanticDiff(ctx, q.get("address_a"), q.get("address_b"), q);
            }
            if ("source".equalsIgnoreCase(mode)) {
                return Diff.compareSource(ctx, q.get("address_a"), q.get("address_b"), q.get("program_b"),
                        Http.parseBool(q.get("clean"), true));
            }
            return Diff.compare(ctx, q.get("address_a"), q.get("address_b"), q.get("program_b"), q);
        });
        routes.getPage("/diff_programs", (p, q) -> Diff.diffPrograms(ctx, q.get("program_b"), p, q));
        routes.postForm("/propagate_matches", p -> Diff.propagateMatches(ctx,
                p.get("program_b"), Http.parseBool(p.get("apply"), false)));
        routes.getPage("/list_scripts", (p, q) -> Scripts.list(p, q));
        routes.getQuery("/pointer_scan", q -> PointerScan.scan(ctx, q.get("target"),
                Http.parseFlexibleLong(q.get("max_offset"), 1024), Http.parseFlexibleLong(q.get("limit"), 100)));
        routes.getQuery("/function_hash", q -> "semantic".equalsIgnoreCase(q.get("mode"))
                ? Emulator.semanticFingerprint(ctx, q.get("address"), q)
                : FunctionHash.hash(ctx, q.get("address"), q));
        routes.getQuery("/recover_rtti_classes", q -> Rtti.recover(ctx, Page.from(q), q));
        routes.getQuery("/find_dynamic_api_resolution", q -> DynamicApi.find(ctx, Page.from(q), q));
        routes.getQuery("/decode_strings_auto", q -> DecodeStrings.decode(ctx, q.get("address"),
                Http.parseIntOrDefault(q.get("length"), 256),
                Double.parseDouble(q.getOrDefault("min_printable", "0.85")),
                Http.parseIntOrDefault(q.get("max"), 10), q));
        routes.getPage("/find_magic_constants", (p, q) -> MagicConstants.find(ctx, p, q));
        routes.postForm("/neutralize_anti_debug", p -> NeutralizeAntiDebug.run(ctx, p));
        routes.postForm("/idiom_simplifier", p -> IdiomSimplifier.run(ctx, p.get("address"), p));
        routes.getQuery("/make_signature", q -> "semantic".equalsIgnoreCase(q.get("mode"))
                ? Emulator.semanticFingerprint(ctx, q.get("address"), q)
                : Signatures.make(ctx, q.get("address"),
                Http.parseIntOrDefault(q.get("min_len"), 0),
                Http.parseIntOrDefault(q.get("max_len"), 0), q.getOrDefault("format", "ida")));
        routes.getQuery("/resolve_relative", q -> Signatures.resolveRelative(ctx, q.get("address")));
        routes.getQuery("/find_function_by_string", q -> Signatures.findFunctionByString(ctx,
                q.get("value"), Http.parseIntOrDefault(q.get("max"), 20), q.getOrDefault("format", "ida"),
                Http.parseBool(q.get("regex"), false), Http.parseBool(q.get("callers"), false)));
        routes.getQuery("/export_offsets", q -> Signatures.exportOffsets(ctx, q.get("filter"),
                Http.parseBool(q.get("regex"), false),
                !"0".equals(q.get("named_only")) && !"false".equalsIgnoreCase(q.getOrDefault("named_only", "1")),
                q.getOrDefault("format", "tsv"), Page.from(q), q));
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
