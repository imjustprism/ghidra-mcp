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

    public static String compare(PluginContext ctx, String addrA, String addrB, String programBName) {
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

        var sb = new StringBuilder();
        sb.append("# diff ").append(funcA.getName()).append(" (").append(program.getName())
                .append(") vs ").append(funcB.getName()).append(" (").append(programB.getName()).append(")\n");
        sb.append("score=").append(score).append("/100\n");
        sb.append("metric\ta\tb\n");
        sb.append("instructions\t").append(ma.instructions()).append('\t').append(mb.instructions()).append('\n');
        sb.append("basic_blocks\t").append(ma.blocks()).append('\t').append(mb.blocks()).append('\n');
        sb.append("mnemonic_jaccard\t").append(pct(mnem)).append("%\n");
        sb.append("call_jaccard\t").append(pct(calls)).append("%\n");
        sb.append("size_ratio\t").append(pct(size)).append("%\n");
        sb.append("calls_a\t").append(Responses.cell(String.join(",", ma.calls()))).append('\n');
        sb.append("calls_b\t").append(Responses.cell(String.join(",", mb.calls()))).append('\n');
        return sb.toString();
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
