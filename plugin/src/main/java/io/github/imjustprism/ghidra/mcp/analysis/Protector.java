package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class Protector {

    private static final double HIGH_ENTROPY = 7.2;

    private Protector() {}

    public static String detect(PluginContext ctx, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var t = Responses.table(q, new String[]{"section", "perms", "entropy", "verdict"}, 8);
            int flagged = 0;
            for (MemoryBlock b : program.getMemory().getBlocks()) {
                var verdict = classify(b);
                if (verdict == null) continue;
                flagged++;
                t.row(b.getName(), perms(b), "%.2f".formatted(Entropy.blockEntropy(b)), verdict);
            }
            var head = flagged == 0
                    ? "# no protector indicators (no known packer section, no RWX high-entropy block)\n"
                    : "# " + flagged + " protector indicator(s) found\n";
            return head + t.total(flagged).build();
        });
    }

    public static List<MemoryBlock> protectedBlocks(Program program) {
        var out = new ArrayList<MemoryBlock>();
        for (MemoryBlock b : program.getMemory().getBlocks()) {
            if (classify(b) != null) out.add(b);
        }
        return out;
    }

    public static String classify(MemoryBlock b) {
        var known = knownProtector(b.getName());
        boolean rwx = b.isRead() && b.isWrite() && b.isExecute();
        if (known != null) return known + (rwx ? " (RWX self-modifying)" : "");
        if (rwx && Entropy.blockEntropy(b) >= HIGH_ENTROPY) {
            return "RWX + high-entropy (packed/virtualized code)";
        }
        return null;
    }

    public static String perms(MemoryBlock b) {
        return (b.isRead() ? "R" : "-") + (b.isWrite() ? "W" : "-") + (b.isExecute() ? "X" : "-");
    }

    private static String knownProtector(String section) {
        var n = section.toLowerCase();
        if (n.startsWith(".vmp")) return "VMProtect";
        if (n.startsWith("upx")) return "UPX";
        return switch (n) {
            case ".vlizer", ".v_lizer" -> "Oreans Code Virtualizer";
            case ".themida", ".winlice" -> "Themida / WinLicense (Oreans)";
            case ".enigma1", ".enigma2" -> "Enigma Protector";
            case ".aspack", ".adata" -> "ASPack";
            case ".asprotect" -> "ASProtect";
            case ".petite" -> "Petite";
            case ".mpress1", ".mpress2" -> "MPRESS";
            case ".nsp0", ".nsp1", ".nsp2" -> "NsPack";
            case ".pelock" -> "PELock";
            case ".y0da", ".yp" -> "yoda's protector";
            default -> null;
        };
    }
}
