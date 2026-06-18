package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public final class Diff {

    private Diff() {}

    private record Metrics(int instructions, int blocks, Map<String, Integer> mnemonics, Set<String> calls) {}

    public static String compare(PluginContext ctx, String addrA, String addrB, String programBName,
            Map<String, String> q) {
        if (addrA == null || addrA.isBlank()) throw new IllegalArgumentException("address_a is required");
        if (addrB == null || addrB.isBlank()) throw new IllegalArgumentException("address_b is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");

        var programB = program;
        if (programBName != null && !programBName.isBlank()) {
            programB = findOpenProgram(ctx, programBName.trim());
            if (programB == null) throw new IllegalArgumentException("program_b is not open: " + programBName);
        }

        var funcA = functionAt(program, addrA, "address_a");
        var funcB = functionAt(programB, addrB, "address_b");
        var ma = metrics(program, funcA);
        var mb = metrics(programB, funcB);

        double mnem = multisetJaccard(ma.mnemonics(), mb.mnemonics());
        double calls = setJaccard(ma.calls(), mb.calls());
        double size = ma.instructions() == 0 && mb.instructions() == 0
                ? 1.0
                : (double) Math.min(ma.instructions(), mb.instructions())
                        / Math.max(ma.instructions(), mb.instructions());
        int score = (int) Math.round(100 * (0.6 * mnem + 0.25 * calls + 0.15 * size));

        var t = Responses.table(q, new String[]{"metric", "value"}, 10);
        t.row("function_a", funcA.getName() + " (" + program.getName() + ")");
        t.row("function_b", funcB.getName() + " (" + programB.getName() + ")");
        t.row("score", score + "/100");
        t.row("instructions", ma.instructions() + " vs " + mb.instructions());
        t.row("basic_blocks", ma.blocks() + " vs " + mb.blocks());
        t.row("mnemonic_jaccard", pct(mnem) + "%");
        t.row("call_jaccard", pct(calls) + "%");
        t.row("size_ratio", pct(size) + "%");
        t.row("calls_a", String.join(",", ma.calls()));
        t.row("calls_b", String.join(",", mb.calls()));
        return t.build();
    }

    public static String diffPrograms(PluginContext ctx, String programBName,
            io.github.imjustprism.ghidra.mcp.http.Page p, Map<String, String> q) {
        if (programBName == null || programBName.isBlank()) throw new IllegalArgumentException("program_b is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var programB = findOpenProgram(ctx, programBName.trim());
        if (programB == null) throw new IllegalArgumentException("program_b is not open: " + programBName);
        if (programB == program) throw new IllegalArgumentException("program_b must differ from the active program");

        var aByHash = hashFunctions(program);
        var bByHash = hashFunctions(programB);
        int totalA = aByHash.values().stream().mapToInt(java.util.List::size).sum();
        int totalB = bByHash.values().stream().mapToInt(java.util.List::size).sum();

        var pairs = new java.util.ArrayList<String[]>();
        int aOnly = 0;
        int bOnly = 0;
        var hashes = new LinkedHashSet<Long>(aByHash.keySet());
        hashes.addAll(bByHash.keySet());
        for (var h : hashes) {
            var la = aByHash.getOrDefault(h, java.util.List.of());
            var lb = bByHash.getOrDefault(h, java.util.List.of());
            int m = Math.min(la.size(), lb.size());
            for (int i = 0; i < m; i++) {
                pairs.add(new String[]{"0x" + Long.toHexString(h), desc(la.get(i)), desc(lb.get(i))});
            }
            aOnly += la.size() - m;
            bOnly += lb.size() - m;
        }

        var t = Responses.table(p, q, new String[]{"shape_hash", "a", "b"});
        var w = new Responses.Window(p);
        for (var pr : pairs) {
            if (w.take()) t.row(pr[0], pr[1], pr[2]);
        }
        return "# diff_programs " + program.getName() + " vs " + programB.getName()
                + ": matched=" + pairs.size() + " a_only=" + aOnly + " b_only=" + bOnly
                + " (A=" + totalA + ", B=" + totalB + ")\n" + t.total(w.total()).build();
    }

    private static final int MAX_PREVIEW = 500;

    public static String propagateMatches(PluginContext ctx, String programBName, boolean apply) {
        if (programBName == null || programBName.isBlank()) throw new IllegalArgumentException("program_b is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var programB = findOpenProgram(ctx, programBName.trim());
        if (programB == null) throw new IllegalArgumentException("program_b is not open: " + programBName);
        if (programB == program) throw new IllegalArgumentException("program_b must differ from the active program");

        var aByHash = hashFunctions(program);
        var bByHash = hashFunctions(programB);
        record Rename(Function target, String oldName, String newName) {}
        var renames = new java.util.ArrayList<Rename>();
        for (var e : aByHash.entrySet()) {
            var la = e.getValue();
            var lb = bByHash.getOrDefault(e.getKey(), java.util.List.of());
            if (la.size() != 1 || lb.size() != 1) continue;
            var fa = la.get(0);
            var fb = lb.get(0);
            if (fa.getSymbol().getSource() != ghidra.program.model.symbol.SourceType.DEFAULT
                    && fb.getSymbol().getSource() == ghidra.program.model.symbol.SourceType.DEFAULT) {
                renames.add(new Rename(fb, fb.getName(), fa.getName()));
            }
        }

        var statuses = new String[renames.size()];
        java.util.Arrays.fill(statuses, "preview");
        if (apply && !renames.isEmpty()) {
            ctx.runOnSwingTx(programB, "Propagate matched names", () -> {
                for (int i = 0; i < renames.size(); i++) {
                    try {
                        renames.get(i).target().setName(renames.get(i).newName(),
                                ghidra.program.model.symbol.SourceType.USER_DEFINED);
                        statuses[i] = "ok";
                    } catch (Exception ex) {
                        statuses[i] = "failed: " + (ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage());
                    }
                }
                return true;
            });
        }

        int applied = 0;
        int failed = 0;
        for (var s : statuses) {
            if (s.equals("ok")) applied++;
            else if (s.startsWith("failed")) failed++;
        }
        var sb = new StringBuilder();
        if (apply) {
            sb.append("# applied ").append(applied).append(" of ").append(renames.size()).append(" name(s)");
            if (failed > 0) sb.append("; ").append(failed).append(" failed");
        } else {
            sb.append("# preview (dry-run, pass apply=1 to commit) ").append(renames.size()).append(" name(s)");
        }
        sb.append(" from ").append(program.getName())
                .append(" onto unique matches in ").append(programB.getName()).append('\n');
        sb.append("address\told\tnew\tstatus\n");
        int shown = Math.min(renames.size(), MAX_PREVIEW);
        for (int i = 0; i < shown; i++) {
            var r = renames.get(i);
            sb.append(Responses.addr(r.target().getEntryPoint())).append('\t')
                    .append(Responses.cell(r.oldName())).append('\t')
                    .append(Responses.cell(r.newName())).append('\t')
                    .append(Responses.cell(statuses[i])).append('\n');
        }
        if (renames.size() > shown) sb.append("# ").append(renames.size() - shown).append(" more not shown\n");
        return sb.toString();
    }

    private static Map<Long, java.util.List<Function>> hashFunctions(Program program) {
        var byHash = new HashMap<Long, java.util.List<Function>>();
        for (var f : program.getFunctionManager().getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) continue;
            if (!program.getListing().getInstructions(f.getBody(), true).hasNext()) continue;
            byHash.computeIfAbsent(FunctionHash.shapeHash(program, f), k -> new java.util.ArrayList<>()).add(f);
        }
        return byHash;
    }

    private static String desc(Function f) {
        return f.getName() + "@" + f.getEntryPoint();
    }

    private static Function functionAt(Program program, String addrStr, String label) {
        var a = program.getAddressFactory().getAddress(addrStr.trim());
        if (a == null) throw new IllegalArgumentException("invalid " + label + ": " + addrStr);
        var f = Addresses.functionAtOrContaining(program, a);
        if (f == null) throw new IllegalArgumentException("no function at " + label + " " + addrStr);
        return f;
    }

    private static Program findOpenProgram(PluginContext ctx, String name) {
        var pm = ctx.service(ProgramManager.class);
        if (pm == null) return null;
        for (var p : pm.getAllOpenPrograms()) {
            if (p.getName().equals(name) || name.equals(p.getExecutableSHA256())) return p;
        }
        return null;
    }

    private static Metrics metrics(Program program, Function func) {
        var mnemonics = new HashMap<String, Integer>();
        var calls = new LinkedHashSet<String>();
        var body = func.getBody();
        int instructions = 0;
        for (var insn : program.getListing().getInstructions(body, true)) {
            instructions++;
            mnemonics.merge(insn.getMnemonicString(), 1, Integer::sum);
            for (var ref : insn.getReferencesFrom()) {
                if (!ref.getReferenceType().isCall()) continue;
                var callee = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                if (callee != null) calls.add(callee.getName());
            }
        }
        int blocks = 0;
        try {
            var it = new BasicBlockModel(program).getCodeBlocksContaining(body, new ConsoleTaskMonitor());
            while (it.hasNext()) {
                it.next();
                blocks++;
            }
        } catch (Exception ignored) {
            blocks = -1;
        }
        return new Metrics(instructions, blocks, mnemonics, calls);
    }

    private static double multisetJaccard(Map<String, Integer> a, Map<String, Integer> b) {
        if (a.isEmpty() && b.isEmpty()) return 1.0;
        long inter = 0;
        long union = 0;
        var keys = new LinkedHashSet<String>(a.keySet());
        keys.addAll(b.keySet());
        for (var k : keys) {
            int ca = a.getOrDefault(k, 0);
            int cb = b.getOrDefault(k, 0);
            inter += Math.min(ca, cb);
            union += Math.max(ca, cb);
        }
        return union == 0 ? 1.0 : (double) inter / union;
    }

    private static double setJaccard(Set<String> a, Set<String> b) {
        if (a.isEmpty() && b.isEmpty()) return 1.0;
        var inter = new LinkedHashSet<>(a);
        inter.retainAll(b);
        var union = new LinkedHashSet<>(a);
        union.addAll(b);
        return union.isEmpty() ? 1.0 : (double) inter.size() / union.size();
    }

    private static int pct(double v) {
        return (int) Math.round(v * 100);
    }
}
