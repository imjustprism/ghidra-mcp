package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.AddressSet;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;
import java.util.TreeSet;

public final class Obfuscation {

    private static final double HIGH_ENTROPY = 7.2;

    private Obfuscation() {}

    public static String profile(PluginContext ctx, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var protectedBlocks = Protector.protectedBlocks(program);
            var set = new AddressSet();
            for (var b : protectedBlocks) set.addRange(b.getStart(), b.getEnd());

            int entrySites = 0;
            var engineTargets = new TreeSet<Long>();
            var srcFns = new TreeSet<String>();
            if (!set.isEmpty()) {
                var rm = program.getReferenceManager();
                var fm = program.getFunctionManager();
                for (var dest : rm.getReferenceDestinationIterator(set, true)) {
                    boolean isEntry = false;
                    for (var ref : rm.getReferencesTo(dest)) {
                        var from = ref.getFromAddress();
                        if (set.contains(from)) continue;
                        if (ref.getReferenceType().isCall() || ref.getReferenceType().isJump()) {
                            isEntry = true;
                            entrySites++;
                            var fn = fm.getFunctionContaining(from);
                            if (fn != null) srcFns.add(fn.getName());
                        }
                    }
                    if (isEntry) engineTargets.add(dest.getOffset());
                }
            }

            int highEntropy = 0;
            for (var b : program.getMemory().getBlocks()) {
                if (Entropy.blockEntropy(b) >= HIGH_ENTROPY) highEntropy++;
            }

            var verdict = verdict(protectedBlocks.isEmpty(), entrySites, highEntropy);
            var sb = new StringBuilder("# obfuscation profile: ").append(verdict).append('\n');
            var t = Responses.table(q, new String[]{"dimension", "value"}, 8);
            t.row("protector_sections", protectedBlocks.isEmpty() ? "none"
                    : protectedBlocks.stream().map(b -> b.getName() + " (" + Protector.classify(b) + ")")
                    .reduce((a, c) -> a + "; " + c).orElse(""));
            t.row("vm_entry_sites", entrySites);
            t.row("vm_engine_targets", engineTargets.size());
            t.row("virtualized_functions", srcFns.size());
            t.row("high_entropy_blocks", highEntropy);
            return sb.append(t.total(5).build()).toString();
        });
    }

    private static String verdict(boolean noProtector, int entrySites, int highEntropy) {
        if (!noProtector && entrySites > 0) return "VIRTUALIZED / PACKED (protector section with code entering it)";
        if (!noProtector) return "PACKED (protector/high-entropy section present, no static code entry)";
        if (highEntropy > 0) return "POSSIBLY PACKED (high-entropy block, no known protector section)";
        return "no protector/packing indicators (clean)";
    }
}
