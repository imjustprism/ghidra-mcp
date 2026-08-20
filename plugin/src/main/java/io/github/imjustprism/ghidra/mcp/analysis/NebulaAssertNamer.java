package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.DecompileCache;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class NebulaAssertNamer {

    private static final int MAX_PREVIEW = 500;
    private static final int DEFAULT_MAX = 200;
    private static final int DISCOVER_CDECL_SAMPLE = 600;

    /** Memoised helper discovery, keyed weakly so a closed program is collectable. */
    private static final Map<Program, List<Helper>> HELPER_CACHE =
            java.util.Collections.synchronizedMap(new WeakHashMap<>());

    private static final Pattern ASSERT_CALL = Pattern.compile(
            "(?:n_assert\\w*|n_verify|FUN_[0-9a-fA-F]+)\\s*\\(\\s*\"([^\"]*)\"\\s*,\\s*\"([^\"]*)\"\\s*,\\s*([^,]+),\\s*\"([^\"]*)\"",
            Pattern.DOTALL);
    private static final Pattern ASSERT_PATH_SIG = Pattern.compile(
            "\\w+\\s*\\(\\s*\"([^\"]+)\"\\s*,\\s*\"([^\"]+\\.(?:cc|cpp|c|h|hpp)[^\"]*)\"\\s*,\\s*([^,]+),\\s*\"([^\"]*(?:__cdecl|__thiscall|__stdcall)[^\"]*)\"",
            Pattern.DOTALL);
    private static final Pattern CALL_CONV = Pattern.compile(
            "\\b__(?:cdecl|stdcall|fastcall|thiscall|vectorcall)\\b");
    private static final Pattern N_ERROR_WARN = Pattern.compile(
            "(?:n_error|n_warning)\\s*\\(\\s*\"((?:[A-Za-z_][\\w:]*(?:<[\\s\\w:,<>]*>)?[\\w:]*)\\([^\"\\n]*)\"",
            Pattern.DOTALL);
    private static final Pattern TYPE_IN_SIG = Pattern.compile("\\b(?:class|struct)\\s+([\\w:]+)");
    private static final Pattern PATH_LINE = Pattern.compile(
            "\"([^\"]+\\.(?:cc|cpp|c|h|hpp))\"\\s*,\\s*([^,\"\\s]+)");
    private static final Pattern CDECL_SIG = Pattern.compile(
            "(?:void|int|bool|char|float|double|long|short|unsigned|class|struct|[A-Za-z_][\\w:]*)"
                    + "[^\"]*__(?:cdecl|thiscall|stdcall)[^\"]*\\(");

    private NebulaAssertNamer() {}

    public static String findHelpers(PluginContext ctx, Map<String, String> q) {
        return ctx.withProgram(program -> {
            ensureNebulaFormatStrings(program);
            var helpers = resolveHelpers(program);
            var t = Responses.table(q, new String[]{"role", "name", "address", "callers", "how"}, 12);
            for (var h : helpers) {
                int callers = h.function().getCallingFunctions(new ConsoleTaskMonitor()).size();
                t.row(h.role(), h.function().getName(), Responses.addr(h.function().getEntryPoint()),
                        callers, h.how());
            }
            var sb = new StringBuilder();
            sb.append("# nebula assert helpers\n");
            if (helpers.isEmpty()) {
                sb.append("# none — run seed_nebula_helpers apply=1 to auto-discover and name them\n");
            }
            sb.append(t.total(helpers.size()).build());
            return sb.toString();
        });
    }

    public static String seedHelpers(PluginContext ctx, boolean apply, Map<String, String> q) {
        if (q != null && "1".equals(q.get("refresh"))) clearHelperCache();
        return ctx.withProgram(program -> {
            // Timed individually: this call dominates the bootstrap chain and the
            // three phases have wildly different costs, so the report says which.
            long t0 = System.nanoTime();
            ensureNebulaFormatStrings(program);
            long msStrings = (System.nanoTime() - t0) / 1_000_000L;
            long t1 = System.nanoTime();
            var discovered = discoverHelpersByCalleeScore(program);
            long msDiscover = (System.nanoTime() - t1) / 1_000_000L;
            long t2 = System.nanoTime();
            var named = resolveHelpers(program);
            long msResolve = (System.nanoTime() - t2) / 1_000_000L;
            record Plan(Function fn, String role, String newName, String how) {}
            var plans = new ArrayList<Plan>();
            var takenRoles = new HashSet<String>();
            for (var h : named) {
                takenRoles.add(h.role());
                plans.add(new Plan(h.function(), h.role(), h.function().getName(), h.how() + " (already)"));
            }
            for (var d : discovered) {
                if (takenRoles.contains(d.role()) && !Responses.isAutoName(d.function().getName())) continue;
                if (!Responses.isAutoName(d.function().getName())
                        && d.function().getSymbol().getSource() != SourceType.DEFAULT) {
                    continue;
                }
                var want = switch (d.role()) {
                    case "n_assert" -> "n_assert";
                    case "n_assert2" -> "n_assert2";
                    case "n_error" -> "n_error";
                    case "n_warning" -> "n_warning";
                    default -> d.role();
                };
                if (takenRoles.contains(d.role()) && d.role().equals("n_assert")) {
                    want = "n_assert2";
                    d = new Helper("n_assert2", d.function(), d.how());
                }
                plans.add(new Plan(d.function(), d.role(), want, d.how()));
                takenRoles.add(d.role());
            }

            var statuses = new String[plans.size()];
            java.util.Arrays.fill(statuses, "preview");
            var applied = new int[1];
            if (apply && !plans.isEmpty()) {
                ctx.runOnSwingTx(program, "Seed nebula helpers", () -> {
                    for (int i = 0; i < plans.size(); i++) {
                        var p = plans.get(i);
                        if (p.how().contains("(already)") && p.fn().getName().equals(p.newName())) {
                            statuses[i] = "ok: already";
                            continue;
                        }
                        try {
                            if (nameTaken(program, p.fn(), p.newName())
                                    && !p.fn().getName().equals(p.newName())) {
                                var alt = p.newName() + "_" + Long.toHexString(p.fn().getEntryPoint().getOffset() & 0xffff);
                                p.fn().setName(alt, SourceType.USER_DEFINED);
                                statuses[i] = "ok: " + alt;
                            } else {
                                p.fn().setName(p.newName(), SourceType.USER_DEFINED);
                                statuses[i] = "ok";
                            }
                            applied[0]++;
                        } catch (Exception e) {
                            statuses[i] = "failed: " + rootMessage(e);
                        }
                    }
                    return true;
                });
            }

            var sb = new StringBuilder();
            sb.append(apply
                    ? "# seeded " + applied[0] + " helper name(s)\n"
                    : "# preview seed_nebula_helpers (pass apply=1)\n");
            sb.append("# timing_ms seed_strings=").append(msStrings)
                    .append(" discover=").append(msDiscover)
                    .append(" resolve=").append(msResolve)
                    .append(" (discover is memoised per program; refresh=1 recomputes)\n");
            sb.append("role\taddress\told\tnew\thow\tstatus\n");
            for (int i = 0; i < plans.size(); i++) {
                var p = plans.get(i);
                sb.append(p.role()).append('\t')
                        .append(Responses.addr(p.fn().getEntryPoint())).append('\t')
                        .append(Responses.cell(p.fn().getName())).append('\t')
                        .append(Responses.cell(p.newName())).append('\t')
                        .append(Responses.cell(p.how())).append('\t')
                        .append(Responses.cell(statuses[i])).append('\n');
            }
            if (plans.isEmpty()) {
                sb.append("# no helpers discovered — binary may lack Nebula asserts\n");
            }
            return sb.toString();
        });
    }

    public static String name(PluginContext ctx, String address, boolean apply, int max,
                              String mode, Map<String, String> q) {
        int cap = max > 0 ? max : DEFAULT_MAX;
        var m = mode == null || mode.isBlank() ? "auto" : mode.trim().toLowerCase(Locale.ROOT);
        return ctx.withProgram(program -> {
            ensureNebulaFormatStrings(program);
            if ("sigs".equals(m) || "signatures".equals(m) || "strings".equals(m)) {
                return nameFromSignatureStrings(ctx, program, address, apply, cap, q);
            }
            if ("decompile".equals(m) || "decomp".equals(m)) {
                return nameFromDecompile(ctx, program, address, apply, cap, q);
            }
            if (address != null && !address.isBlank()) {
                return nameFromDecompile(ctx, program, address, apply, cap, q);
            }
            var sigPart = nameFromSignatureStrings(ctx, program, null, apply, cap, q);
            if (cap <= 0) return sigPart;
            int remain = Math.max(0, cap - countStatusOk(sigPart));
            if (remain == 0 && !apply) return sigPart + "# tip: mode=decompile for assert-callers missed by string xrefs\n";
            if ("auto".equals(m) && remain > 0 && apply) {
                var decompPart = nameFromDecompile(ctx, program, null, true, remain, q);
                return sigPart + "\n# --- decompile fill-in ---\n" + decompPart;
            }
            if ("auto".equals(m) && !apply) {
                return sigPart + "# mode=auto dry-run shows signature-string hits only; "
                        + "use mode=decompile for assert-caller decomp path, or apply=1 for sigs then decomp fill\n";
            }
            return sigPart;
        });
    }

    public static String nameFromSignatures(PluginContext ctx, String address, boolean apply, int max,
                                            Map<String, String> q) {
        int cap = max > 0 ? max : DEFAULT_MAX;
        return ctx.withProgram(program ->
                nameFromSignatureStrings(ctx, program, address, apply, cap, q));
    }

    public static String survey(PluginContext ctx, Map<String, String> q) {
        return ctx.withProgram(program -> {
            ensureNebulaFormatStrings(program);
            var helpers = resolveHelpers(program);
            int auto = 0;
            int total = 0;
            for (var f : program.getFunctionManager().getFunctions(true)) {
                if (f.isExternal() || f.isThunk()) continue;
                total++;
                if (Responses.isAutoName(f.getName())) auto++;
            }
            int callerPool = 0;
            var seen = new HashSet<Long>();
            var mon = new ConsoleTaskMonitor();
            for (var h : helpers) {
                for (var c : h.function().getCallingFunctions(mon)) {
                    if (seen.add(c.getEntryPoint().getOffset()) && Responses.isAutoName(c.getName())) {
                        callerPool++;
                    }
                }
            }
            var sigStats = countSignatureNameable(program);
            var t = Responses.table(q, new String[]{"k", "v"}, 16);
            t.row("functions", total);
            t.row("auto_named", auto);
            t.row("named_functions", total - auto);
            t.row("assert_helpers", helpers.size());
            t.row("auto_named_assert_callers", callerPool);
            t.row("cdecl_signature_strings", sigStats[0]);
            t.row("sig_unique_auto_nameable", sigStats[1]);
            t.row("sig_multi_function", sigStats[2]);
            t.row("sig_already_named", sigStats[3]);
            var sb = new StringBuilder();
            sb.append("# nebula_engine_survey\n");
            sb.append(t.total(9).build());
            if (!helpers.isEmpty()) {
                sb.append("# helpers\n");
                for (var h : helpers) {
                    sb.append(h.role()).append('\t').append(h.function().getName()).append('\t')
                            .append(Responses.addr(h.function().getEntryPoint())).append('\t')
                            .append(h.how()).append('\n');
                }
            } else {
                sb.append("# tip: seed_nebula_helpers apply=1\n");
            }
            sb.append("# next: name_from_signatures (fast, ~")
                    .append(sigStats[1]).append(" ready) → name_from_n_assert mode=decompile → ")
                    .append("name_nebula_instances → derive_tls_singletons apply=true → ")
                    .append("factory_catalog / assert_catalog / messaging_catalog / attr_catalog / ")
                    .append("source_tree / funcsig_graph\n");
            return sb.toString();
        });
    }

    private static String nameFromSignatureStrings(PluginContext ctx, Program program, String address,
                                                   boolean apply, int max, Map<String, String> q) {
        var hits = new ArrayList<Hit>();
        var types = new LinkedHashSet<String>();
        var claimed = new HashSet<Long>();
        var usedNames = new HashSet<String>();

        if (address != null && !address.isBlank()) {
            var a = Addresses.resolve(program, address.trim());
            if (a == null) throw new IllegalArgumentException("invalid address: " + address);
            var fn = Addresses.functionAtOrContaining(program, a);
            if (fn == null) throw new IllegalArgumentException("no function at " + address);
            var hit = bestSignatureForFunction(program, fn);
            if (hit != null) {
                ensureTypesFromText(hit.signature(), types);
                hits.add(new Hit(fn, fn.getName(), hit.ghidraName(), "sig_string",
                        hit.file(), hit.line(), hit.signature()));
            }
        } else {
            var listing = program.getListing();
            var fm = program.getFunctionManager();
            var refMgr = program.getReferenceManager();
            var it = listing.getDefinedData(true);
            while (it.hasNext() && hits.size() < max) {
                var data = it.next();
                if (data == null || !DataTypes.isStringLike(data) || data.getValue() == null) continue;
                var raw = data.getValue().toString();
                if (!isCdeclSignature(raw)) continue;
                var extracted = fromSignatureString(raw);
                if (extracted == null) continue;
                Function only = null;
                int distinct = 0;
                for (var ref : refMgr.getReferencesTo(data.getAddress())) {
                    var fn = fm.getFunctionContaining(ref.getFromAddress());
                    if (fn == null || fn.isExternal() || fn.isThunk()) continue;
                    if (only == null || !only.getEntryPoint().equals(fn.getEntryPoint())) {
                        distinct++;
                        only = fn;
                        if (distinct > 1) break;
                    }
                }
                if (distinct != 1 || only == null) continue;
                if (!Responses.isAutoName(only.getName())
                        && only.getSymbol().getSource() != SourceType.DEFAULT) continue;
                if (!claimed.add(only.getEntryPoint().getOffset())) continue;
                var gname = extracted.ghidraName();
                if (!usedNames.add(gname)) {
                    gname = gname + "_" + Long.toHexString(only.getEntryPoint().getOffset() & 0xfffff);
                    usedNames.add(gname);
                }
                ensureTypesFromText(extracted.signature(), types);
                hits.add(new Hit(only, only.getName(), gname, "sig_string",
                        extracted.file(), extracted.line(), extracted.signature()));
            }
        }

        return commitHits(ctx, program, hits, types, apply, "signature-strings", List.of());
    }

    private static String nameFromDecompile(PluginContext ctx, Program program, String address,
                                            boolean apply, int max, Map<String, String> q) {
        var helpers = resolveHelpers(program);
        if (helpers.isEmpty()) {
            helpers = discoverHelpersByCalleeScore(program);
        }
        if (helpers.isEmpty() && (address == null || address.isBlank())) {
            return "# no n_assert / n_error helpers found\n"
                    + "# run seed_nebula_helpers apply=1  OR  name_from_signatures\n";
        }

        int scanCap = address != null && !address.isBlank()
                ? 1
                : Math.min(Math.max(max * 25, 200), 5000);
        var candidates = collectCandidates(program, helpers, address, scanCap);
        var hits = new ArrayList<Hit>();
        var types = new LinkedHashSet<String>();
        var usedNames = new HashSet<String>();

        for (var fn : candidates) {
            if (hits.size() >= max) break;
            if (!Responses.isAutoName(fn.getName()) && fn.getSymbol().getSource() != SourceType.DEFAULT) {
                continue;
            }
            String c;
            try {
                c = DecompileCache.decompile(program, fn);
            } catch (RuntimeException e) {
                continue;
            }
            if (c == null || c.isBlank() || c.startsWith("Decompilation failed")) continue;
            var extracted = extractName(c);
            if (extracted == null) continue;
            ensureTypesFromText(extracted.signature(), types);
            var gname = extracted.ghidraName();
            if (!usedNames.add(gname)) {
                gname = gname + "_" + Long.toHexString(fn.getEntryPoint().getOffset() & 0xfffff);
                usedNames.add(gname);
            }
            hits.add(new Hit(fn, fn.getName(), gname, extracted.source(),
                    extracted.file(), extracted.line(), extracted.signature()));
        }
        return commitHits(ctx, program, hits, types, apply, "decompile", helpers);
    }

    private static String commitHits(PluginContext ctx, Program program,
                                     List<Hit> hits, Set<String> types,
                                     boolean apply, String mode, List<Helper> helpers) {
        var statuses = new String[hits.size()];
        java.util.Arrays.fill(statuses, "preview");
        var applied = new int[1];
        if (apply && !hits.isEmpty()) {
            ctx.runOnSwingTx(program, "Nebula name " + mode, () -> {
                definePlaceholderTypes(program, types);
                for (int i = 0; i < hits.size(); i++) {
                    var h = hits.get(i);
                    try {
                        if (!Responses.isAutoName(h.function().getName())
                                && h.function().getSymbol().getSource() != SourceType.DEFAULT) {
                            statuses[i] = "skipped: already named";
                            continue;
                        }
                        var newName = h.newName();
                        if (nameTaken(program, h.function(), newName)) {
                            newName = newName + "_" + Long.toHexString(h.function().getEntryPoint().getOffset() & 0xfffff);
                            if (nameTaken(program, h.function(), newName)) {
                                statuses[i] = "failed: name exists";
                                continue;
                            }
                        }
                        h.function().setName(newName, SourceType.USER_DEFINED);
                        if (h.file() != null && !h.file().isBlank()) {
                            var note = h.file() + (h.line() != null ? ":" + h.line() : "");
                            if (h.signature() != null && !h.signature().isBlank()) {
                                note = note + " | " + h.signature();
                            }
                            program.getListing().setComment(h.function().getEntryPoint(),
                                    ghidra.program.model.listing.CodeUnit.PLATE_COMMENT, note);
                        }
                        statuses[i] = "ok";
                        applied[0]++;
                    } catch (Exception e) {
                        statuses[i] = "failed: " + rootMessage(e);
                        Msg.error(ctx.logOwner(), "nebula rename failed " + h.oldName(), e);
                    }
                }
                return true;
            });
        }

        int failed = 0;
        int skipped = 0;
        for (var s : statuses) {
            if (s.startsWith("failed")) failed++;
            else if (s.startsWith("skipped")) skipped++;
        }
        var sb = new StringBuilder();
        if (apply) {
            sb.append("# applied ").append(applied[0]).append(" of ").append(hits.size())
                    .append(" rename(s) mode=").append(mode);
            if (failed > 0) sb.append("; ").append(failed).append(" failed");
            if (skipped > 0) sb.append("; ").append(skipped).append(" skipped");
        } else {
            sb.append("# preview (dry-run, pass apply=1) ").append(hits.size())
                    .append(" rename(s) mode=").append(mode);
        }
        sb.append('\n');
        if (!helpers.isEmpty()) {
            sb.append("# helpers:");
            for (var h : helpers) {
                sb.append(' ').append(h.role()).append('@').append(Responses.addr(h.function().getEntryPoint()));
            }
            sb.append('\n');
        }
        sb.append("# named=").append(hits.size()).append('\n');
        if (!types.isEmpty() && apply) {
            sb.append("# placeholder types defined: ").append(types.size()).append('\n');
        }
        sb.append("address\told\tnew\tsource\tfile\tstatus\n");
        int shown = Math.min(hits.size(), MAX_PREVIEW);
        for (int i = 0; i < shown; i++) {
            var h = hits.get(i);
            sb.append(Responses.addr(h.function().getEntryPoint())).append('\t')
                    .append(Responses.cell(h.oldName())).append('\t')
                    .append(Responses.cell(h.newName())).append('\t')
                    .append(Responses.cell(h.source())).append('\t')
                    .append(Responses.cell(h.file() == null ? "" : h.file()
                            + (h.line() == null ? "" : ":" + h.line()))).append('\t')
                    .append(Responses.cell(statuses[i])).append('\n');
        }
        if (hits.size() > shown) {
            sb.append("# ").append(hits.size() - shown).append(" more not shown\n");
        }
        return sb.toString();
    }

    record Hit(Function function, String oldName, String newName, String source,
               String file, String line, String signature) {}

    record Helper(String role, Function function, String how) {}

    record Extracted(String ghidraName, String source, String file, String line, String signature) {}

    static List<Helper> resolveHelpers(Program program) {
        var byKey = new LinkedHashMap<String, Helper>();
        var fm = program.getFunctionManager();
        for (var f : fm.getFunctions(true)) {
            var n = f.getName();
            if (n == null) continue;
            var lower = n.toLowerCase(Locale.ROOT);
            if (lower.equals("n_assert") || lower.equals("nassert")) {
                putHelper(byKey, "n_assert", f, "name");
            } else if (lower.equals("n_assert2") || lower.equals("n_verify") || lower.equals("n_assert_msg")) {
                putHelper(byKey, "n_assert2", f, "name");
            } else if (lower.equals("n_error") || lower.endsWith("::n_error")) {
                putHelper(byKey, "n_error", f, "name");
            } else if (lower.equals("n_warning") || lower.endsWith("::n_warning")) {
                putHelper(byKey, "n_warning", f, "name");
            }
        }
        for (var hit : stringFunctions(program, "NEBULA ASSERTION")) {
            putHelper(byKey, "n_assert", hit, "string:NEBULA ASSERTION");
        }
        for (var hit : stringFunctions(program, "NEBULA CRITICAL")) {
            putHelper(byKey, "n_assert2", hit, "string:NEBULA CRITICAL");
        }
        boolean hasNamedWarning = byKey.values().stream().anyMatch(h -> "n_warning".equals(h.role())
                && "name".equals(h.how()));
        if (!hasNamedWarning) {
            for (var hit : stringFunctions(program, "IO::Console::Warning")) {
                var ln = hit.getName().toLowerCase(Locale.ROOT);
                if (ln.contains("warning") || Responses.isAutoName(hit.getName())) {
                    putHelper(byKey, "n_warning", hit, "string:IO::Console::Warning");
                }
            }
        }
        if (byKey.isEmpty() || countRole(byKey, "n_assert") == 0) {
            for (var d : discoverHelpersByCalleeScore(program)) {
                putHelper(byKey, d.role(), d.function(), d.how());
            }
        }
        return new ArrayList<>(byKey.values());
    }

    private static int countRole(Map<String, Helper> byKey, String role) {
        int n = 0;
        for (var h : byKey.values()) if (role.equals(h.role())) n++;
        return n;
    }

    /**
     * Which functions are n_assert / n_assert2 / n_error / n_warning.
     *
     * <p>Memoised per program. The computation walks up to
     * {@link #DISCOVER_CDECL_SAMPLE} signature strings and, for every function
     * referencing one, enumerates its callees — on a client where a single
     * assert string has thousands of references that is minutes of work, and it
     * used to run again on every call from seedHelpers, name() and survey().
     *
     * <p>Caching across edits is deliberate: renaming the helpers does not change
     * <em>which</em> functions they are, and {@code resolveHelpers} already picks
     * up anything that has since been named. Call {@link #clearHelperCache} after
     * re-analysis, or pass {@code refresh=1}.
     */
    static List<Helper> discoverHelpersByCalleeScore(Program program) {
        var cached = HELPER_CACHE.get(program);
        if (cached != null) return cached;
        var computed = computeHelpersByCalleeScore(program);
        HELPER_CACHE.put(program, computed);
        return computed;
    }

    /** Drop the memoised helper discovery, e.g. after re-running analysis. */
    public static void clearHelperCache() {
        HELPER_CACHE.clear();
    }

    private static List<Helper> computeHelpersByCalleeScore(Program program) {
        var fm = program.getFunctionManager();
        var mon = new ConsoleTaskMonitor();
        var scores = new HashMap<Long, int[]>();
        var funcs = new HashMap<Long, Function>();
        int scanned = 0;
        var it = program.getListing().getDefinedData(true);
        while (it.hasNext() && scanned < DISCOVER_CDECL_SAMPLE) {
            var data = it.next();
            if (data == null || data.getValue() == null) continue;
            var s = data.getValue().toString();
            if (!isCdeclSignature(s)) continue;
            scanned++;
            for (var ref : program.getReferenceManager().getReferencesTo(data.getAddress())) {
                var fn = fm.getFunctionContaining(ref.getFromAddress());
                if (fn == null) continue;
                for (var cal : fn.getCalledFunctions(mon)) {
                    long k = cal.getEntryPoint().getOffset();
                    funcs.put(k, cal);
                    scores.computeIfAbsent(k, x -> new int[]{0})[0]++;
                }
            }
        }
        var ranked = new ArrayList<>(scores.entrySet());
        ranked.sort(Comparator.<Map.Entry<Long, int[]>>comparingInt(e -> e.getValue()[0]).reversed());
        var out = new ArrayList<Helper>();
        for (var e : ranked) {
            if (e.getValue()[0] < 50) break;
            var f = funcs.get(e.getKey());
            if (f == null) continue;
            String c;
            try {
                c = DecompileCache.decompile(program, f);
            } catch (RuntimeException ex) {
                continue;
            }
            if (c == null) continue;
            if (c.contains("NEBULA ASSERTION") || c.contains("1412098b0") || c.contains("DAT_1412098")
                    || (c.contains("param_4") && c.contains("param_3") && c.contains("param_1"))) {
                if (c.contains("NEBULA CRITICAL") || c.contains("141209900") || c.contains("141209964")) {
                    out.add(new Helper("n_assert2", f, "callee_score=" + e.getValue()[0]));
                } else if (c.contains("vfwprintf") || c.contains("Console::Warning")
                        || c.contains("IO_Console_Warning")) {
                    out.add(new Helper("n_warning", f, "callee_score=" + e.getValue()[0]));
                } else if (out.stream().noneMatch(h -> "n_assert".equals(h.role()))) {
                    out.add(new Helper("n_assert", f, "callee_score=" + e.getValue()[0]));
                } else if (out.stream().noneMatch(h -> "n_error".equals(h.role()))
                        && (c.contains("n_error") || c.contains("param_1") && c.contains("DAT_"))) {
                    if (c.contains("auStack") && c.contains("param_1")) {
                        out.add(new Helper(out.stream().anyMatch(h -> "n_assert".equals(h.role()))
                                ? "n_error" : "n_assert", f, "callee_score=" + e.getValue()[0]));
                    }
                } else if (out.stream().noneMatch(h -> "n_assert2".equals(h.role()))
                        && e.getValue()[0] > 500) {
                    out.add(new Helper("n_assert2", f, "callee_score=" + e.getValue()[0]));
                }
            }
            if (out.size() >= 6) break;
        }
        for (var e : ranked) {
            if (out.stream().anyMatch(h -> "n_error".equals(h.role()))) break;
            var f = funcs.get(e.getKey());
            if (f == null || e.getValue()[0] < 100) continue;
            String c;
            try {
                c = DecompileCache.decompile(program, f);
            } catch (RuntimeException ex) {
                continue;
            }
            if (c != null && c.contains("n_error") == false && c.contains("DAT_1412098")
                    && f.getName().toLowerCase(Locale.ROOT).contains("assert")) {
                continue;
            }
            if (c != null && (c.contains("1412098b0") || c.contains("NEBULA ASSERTION"))
                    && out.stream().noneMatch(h -> h.function().getEntryPoint().equals(f.getEntryPoint()))) {
                out.add(new Helper("n_error", f, "callee_score=" + e.getValue()[0] + ",error_path"));
            }
        }
        return out;
    }

    private static void putHelper(Map<String, Helper> byKey, String role, Function f, String how) {
        byKey.putIfAbsent(role + "@" + f.getEntryPoint(), new Helper(role, f, how));
    }

    private static List<Function> stringFunctions(Program program, String needle) {
        var out = new ArrayList<Function>();
        var listing = program.getListing();
        var fm = program.getFunctionManager();
        var refMgr = program.getReferenceManager();
        var seen = new HashSet<Long>();
        var lower = needle.toLowerCase(Locale.ROOT);
        var it = listing.getDefinedData(true);
        while (it.hasNext()) {
            var data = it.next();
            if (data == null || !DataTypes.isStringLike(data)) continue;
            var sv = data.getValue() != null ? data.getValue().toString() : "";
            if (!sv.toLowerCase(Locale.ROOT).contains(lower)) continue;
            for (var ref : refMgr.getReferencesTo(data.getAddress())) {
                var fn = fm.getFunctionContaining(ref.getFromAddress());
                if (fn == null || !seen.add(fn.getEntryPoint().getOffset())) continue;
                out.add(fn);
            }
        }
        return out;
    }

    private static void ensureNebulaFormatStrings(Program program) {
        try {
            seedStringIfPresent(program, "NEBULA ASSERTION");
            seedStringIfPresent(program, "NEBULA CRITICAL");
            seedStringIfPresent(program, "NEBULA3 MESSAGE");
        } catch (Exception ignored) {
        }
    }

    private static void seedStringIfPresent(Program program, String needle) {
        var mem = program.getMemory();
        var mon = new ConsoleTaskMonitor();
        byte[] bytes = needle.getBytes(StandardCharsets.US_ASCII);
        Address found = mem.findBytes(mem.getMinAddress(), bytes, null, true, mon);
        int n = 0;
        while (found != null && n < 8) {
            tryDefineString(program, found);
            Address start = found;
            try {
                start = found.subtract(16);
            } catch (Exception ignored) {
            }
            for (int back = 0; back < 16; back++) {
                try {
                    var a = found.subtract(back);
                    if (mem.getByte(a) == (byte) '*') {
                        tryDefineString(program, a);
                        break;
                    }
                } catch (Exception ignored) {
                }
            }
            found = mem.findBytes(found.add(1), bytes, null, true, mon);
            n++;
        }
    }

    private static void tryDefineString(Program program, Address a) {
        try {
            var listing = program.getListing();
            Data existing = listing.getDefinedDataAt(a);
            if (existing != null && DataTypes.isStringLike(existing)) return;
            if (existing != null) return;
            int tx = program.startTransaction("Define nebula string");
            boolean ok = false;
            try {
                listing.clearCodeUnits(a, a, false);
                listing.createData(a, StringDataType.dataType);
                ok = true;
            } catch (Exception e) {
                try {
                    listing.createData(a, ByteDataType.dataType);
                } catch (Exception ignored) {
                }
            } finally {
                program.endTransaction(tx, ok);
            }
        } catch (Exception ignored) {
        }
    }

    private static List<Function> collectCandidates(Program program, List<Helper> helpers,
                                                    String address, int max) {
        var out = new ArrayList<Function>();
        var seen = new HashSet<Long>();
        if (address != null && !address.isBlank()) {
            var a = Addresses.resolve(program, address.trim());
            if (a == null) throw new IllegalArgumentException("invalid address: " + address);
            var f = Addresses.functionAtOrContaining(program, a);
            if (f == null) throw new IllegalArgumentException("no function at " + address);
            out.add(f);
            return out;
        }
        var mon = new ConsoleTaskMonitor();
        for (var h : helpers) {
            for (var c : h.function().getCallingFunctions(mon)) {
                if (c.isExternal() || c.isThunk()) continue;
                if (!Responses.isAutoName(c.getName()) && c.getSymbol().getSource() != SourceType.DEFAULT) {
                    continue;
                }
                if (!seen.add(c.getEntryPoint().getOffset())) continue;
                out.add(c);
                if (out.size() >= max) return out;
            }
        }
        return out;
    }

    static Extracted extractName(String decompiled) {
        var fromAssert = fromAssertCall(decompiled);
        if (fromAssert != null) return fromAssert;
        return fromErrorWarning(decompiled);
    }

    static Extracted fromAssertCall(String decompiled) {
        Matcher m = ASSERT_CALL.matcher(decompiled);
        if (!m.find()) {
            m = ASSERT_PATH_SIG.matcher(decompiled);
            if (!m.find()) return null;
            m.reset();
            if (!m.find()) return null;
        } else {
            m.reset();
        }
        var names = new ArrayList<String>();
        var sigs = new ArrayList<String>();
        String file = null;
        String line = null;
        Matcher mm = ASSERT_CALL.matcher(decompiled);
        boolean any = false;
        while (mm.find()) {
            any = true;
            if (file == null && mm.group(2) != null && !mm.group(2).isBlank()) {
                file = mm.group(2);
                line = normalizeLine(mm.group(3));
            }
            var sig = mm.group(4);
            if (sig == null) continue;
            var q = qualifiedFromSignature(sig);
            if (q == null) continue;
            names.add(q);
            sigs.add(sig);
        }
        if (!any) {
            mm = ASSERT_PATH_SIG.matcher(decompiled);
            while (mm.find()) {
                if (file == null && mm.group(2) != null && !mm.group(2).isBlank()) {
                    file = mm.group(2);
                    line = normalizeLine(mm.group(3));
                }
                var sig = mm.group(4);
                if (sig == null) continue;
                var q = qualifiedFromSignature(sig);
                if (q == null) continue;
                names.add(q);
                sigs.add(sig);
            }
        }
        if (names.isEmpty()) return null;
        var unique = new LinkedHashSet<>(names);
        if (unique.size() != 1) return null;
        var name = names.get(0);
        if (isInstanceOnly(name)) return null;
        return new Extracted(sanitize(name), "n_assert", file, line, sigs.get(0));
    }

    static Extracted fromErrorWarning(String decompiled) {
        Matcher m = N_ERROR_WARN.matcher(decompiled);
        if (!m.find()) return null;
        var raw = m.group(1);
        int paren = raw.indexOf('(');
        var head = paren > 0 ? raw.substring(0, paren) : raw;
        head = head.replace("class ", "").trim();
        if (head.isBlank() || head.contains("%")) return null;
        if (isInstanceOnly(head)) return null;
        String file = null;
        String line = null;
        Matcher pl = PATH_LINE.matcher(decompiled);
        if (pl.find()) {
            file = pl.group(1);
            line = normalizeLine(pl.group(2));
        }
        var source = decompiled.contains("n_warning") && !decompiled.contains("n_error")
                ? "n_warning" : "n_error";
        return new Extracted(sanitize(head), source, file, line, raw);
    }

    static Extracted fromSignatureString(String raw) {
        if (raw == null || !isCdeclSignature(raw)) return null;
        var q = qualifiedFromSignature(raw);
        if (q == null || isInstanceOnly(q)) return null;
        return new Extracted(sanitize(q), "sig_string", null, null, raw);
    }

    static Extracted bestSignatureForFunction(Program program, Function fn) {
        var refMgr = program.getReferenceManager();
        Extracted best = null;
        int bestScore = -1;
        for (var addr : fn.getBody().getAddresses(true)) {
            for (var ref : refMgr.getReferencesFrom(addr)) {
                if (!ref.getReferenceType().isData() && !ref.getReferenceType().isRead()) continue;
                var data = program.getListing().getDefinedDataAt(ref.getToAddress());
                if (data == null || data.getValue() == null) continue;
                var s = data.getValue().toString();
                if (!isCdeclSignature(s)) continue;
                var ex = fromSignatureString(s);
                if (ex == null) continue;
                int score = s.length();
                if (score > bestScore) {
                    bestScore = score;
                    best = ex;
                }
            }
        }
        return best;
    }

    static boolean isCdeclSignature(String s) {
        if (s == null || s.length() < 16) return false;
        if (!s.contains("__cdecl") && !s.contains("__thiscall") && !s.contains("__stdcall")) return false;
        return s.indexOf('(') > 0 && CDECL_SIG.matcher(s).find();
    }

    static boolean isInstanceOnly(String name) {
        if (name == null) return true;
        var n = name.trim();
        return n.equals("Instance") || n.endsWith("::Instance") || n.endsWith("_Instance");
    }

    static String qualifiedFromSignature(String sig) {
        if (sig == null || sig.isBlank()) return null;
        int paren = indexOfTopLevel(sig, '(');
        if (paren <= 0) paren = sig.lastIndexOf('(');
        if (paren <= 0) return null;
        var head = sig.substring(0, paren).trim();
        var cc = CALL_CONV.matcher(head);
        if (cc.find()) {
            head = head.substring(cc.end()).trim();
        } else {
            int sp = lastTopLevelSpace(head);
            if (sp >= 0) head = head.substring(sp + 1).trim();
        }
        head = head.replace("class ", "").replace("struct ", "").trim();
        if (head.isBlank()) return null;
        return head;
    }

    static String sanitize(String qualified) {
        if (qualified == null) return "";
        var s = replaceInBrackets(qualified, "::", "_");
        s = s.replace("class ", "").replace("struct ", "");
        s = s.replace("operator ", "operator");
        s = s.replace(" ", "");
        s = s.replace('<', '6').replace('>', '9').replace(',', '1');
        s = s.replace("::", "_");
        s = s.replaceAll("[^A-Za-z0-9_]", "_");
        s = s.replaceAll("_+", "_");
        if (s.startsWith("_")) s = s.substring(1);
        if (s.endsWith("_")) s = s.substring(0, s.length() - 1);
        if (s.isEmpty()) return "unnamed";
        if (Character.isDigit(s.charAt(0))) s = "n_" + s;
        if (s.length() > 200) s = s.substring(0, 200);
        return s;
    }

    static String replaceInBrackets(String text, String old, String neu) {
        int lt = text.indexOf('<');
        int gt = text.lastIndexOf('>');
        if (lt < 0 || gt <= lt) return text;
        var mid = text.substring(lt + 1, gt).replace(old, neu);
        return text.substring(0, lt + 1) + mid + text.substring(gt);
    }

    static int indexOfTopLevel(String s, char needle) {
        int depth = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '<') depth++;
            else if (c == '>') depth = Math.max(0, depth - 1);
            else if (c == needle && depth == 0) return i;
        }
        return -1;
    }

    static int lastTopLevelSpace(String s) {
        int depth = 0;
        int last = -1;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '<') depth++;
            else if (c == '>') depth = Math.max(0, depth - 1);
            else if (c == ' ' && depth == 0) last = i;
        }
        return last;
    }

    static String normalizeLine(String raw) {
        if (raw == null) return null;
        var t = raw.trim();
        if (t.startsWith("0x") || t.startsWith("0X")) {
            try {
                return Integer.toString(Integer.parseInt(t.substring(2), 16));
            } catch (NumberFormatException e) {
                return t;
            }
        }
        return t;
    }

    static void ensureTypesFromText(String sig, Set<String> types) {
        if (sig == null) return;
        Matcher m = TYPE_IN_SIG.matcher(sig);
        while (m.find()) types.add(m.group(1).trim());
    }

    private static void definePlaceholderTypes(Program program, Set<String> types) {
        if (types == null || types.isEmpty()) return;
        var dtm = program.getDataTypeManager();
        for (var typeName : types) {
            if (typeName == null || typeName.isBlank()) continue;
            var simple = typeName.contains("::")
                    ? typeName.substring(typeName.lastIndexOf("::") + 2) : typeName;
            boolean found = false;
            var it = dtm.getAllDataTypes();
            while (it.hasNext()) {
                var dt = it.next();
                if (simple.equals(dt.getName()) || typeName.equals(dt.getName())) {
                    found = true;
                    break;
                }
            }
            if (found) continue;
            try {
                var placeholder = new StructureDataType(simple, 0);
                dtm.addDataType(placeholder, DataTypeConflictHandler.DEFAULT_HANDLER);
            } catch (Exception ignored) {
            }
        }
    }

    private static boolean nameTaken(Program program, Function fn, String newName) {
        var st = program.getSymbolTable();
        var ns = fn.getParentNamespace();
        for (var sym : st.getSymbols(newName, ns)) {
            if (sym.getAddress().equals(fn.getEntryPoint())) return false;
            return true;
        }
        return false;
    }

    private static int[] countSignatureNameable(Program program) {
        int sigs = 0, nameable = 0, multi = 0, named = 0;
        var fm = program.getFunctionManager();
        var refMgr = program.getReferenceManager();
        var it = program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            var data = it.next();
            if (data == null || data.getValue() == null) continue;
            var s = data.getValue().toString();
            if (!isCdeclSignature(s)) continue;
            sigs++;
            var set = new HashSet<Long>();
            Function only = null;
            for (var ref : refMgr.getReferencesTo(data.getAddress())) {
                var fn = fm.getFunctionContaining(ref.getFromAddress());
                if (fn == null) continue;
                set.add(fn.getEntryPoint().getOffset());
                only = fn;
            }
            if (set.isEmpty()) continue;
            if (set.size() > 1) multi++;
            else if (only != null) {
                if (Responses.isAutoName(only.getName())
                        || only.getSymbol().getSource() == SourceType.DEFAULT) nameable++;
                else named++;
            }
        }
        return new int[]{sigs, nameable, multi, named};
    }

    private static int countStatusOk(String report) {
        int n = 0;
        for (var line : report.split("\n")) {
            if (line.endsWith("\tpreview") || line.endsWith("\tok")) n++;
        }
        return n;
    }

    private static String rootMessage(Throwable e) {
        var t = e;
        while (t.getCause() != null && t.getCause() != t) t = t.getCause();
        var m = t.getMessage();
        return m == null || m.isBlank() ? t.getClass().getSimpleName() : m;
    }
}
