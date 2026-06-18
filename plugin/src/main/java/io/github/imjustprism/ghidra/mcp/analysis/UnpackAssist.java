package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public final class UnpackAssist {

    private static final double HIGH_ENTROPY = 7.0;
    private static final int FEW_IMPORTS = 12;

    private static final Map<String, String> PACKER_SECTIONS = packerSections();

    private UnpackAssist() {}

    public static String report(PluginContext ctx) {
        return ctx.withProgram(UnpackAssist::analyze);
    }

    private static String analyze(Program program) {
        var rows = new StringBuilder();
        int score = 0;
        String packer = null;

        double maxCodeEntropy = 0;
        String hottestBlock = null;
        boolean rwx = false;
        String rwxBlock = null;
        for (var block : program.getMemory().getBlocks()) {
            var sig = PACKER_SECTIONS.get(normalizeSection(block.getName()));
            if (sig != null && packer == null) packer = sig;
            if (block.isWrite() && block.isExecute()) {
                rwx = true;
                if (rwxBlock == null) rwxBlock = block.getName();
            }
            if (block.isExecute()) {
                double e = Entropy.blockEntropy(block);
                if (e > maxCodeEntropy) {
                    maxCodeEntropy = e;
                    hottestBlock = block.getName();
                }
            }
        }

        int imports = 0;
        for (var ignored : program.getFunctionManager().getExternalFunctions()) imports++;

        String oepBlock = null;
        for (var sym : program.getSymbolTable().getGlobalSymbols("entry")) {
            var block = program.getMemory().getBlock(sym.getAddress());
            if (block != null && block.isWrite()) {
                oepBlock = block.getName();
                break;
            }
        }

        if (packer != null) {
            score += 35;
            row(rows, "packer_section", "matched " + packer, 35);
        }
        if (maxCodeEntropy >= HIGH_ENTROPY) {
            score += 25;
            row(rows, "high_entropy_code", "%s entropy %.2f".formatted(hottestBlock, maxCodeEntropy), 25);
        }
        if (rwx) {
            score += 20;
            row(rows, "rwx_section", rwxBlock + " is writable+executable", 20);
        }
        if (imports < FEW_IMPORTS) {
            score += 15;
            row(rows, "few_imports", imports + " imported symbols", 15);
        }
        if (oepBlock != null) {
            score += 15;
            row(rows, "oep_writable", "entry point in writable block " + oepBlock, 15);
        }
        score = Math.min(score, 100);

        var verdict = score >= 70 ? "likely_packed" : score >= 40 ? "possibly_packed" : "unlikely_packed";
        var sb = new StringBuilder("# unpack_assist\n");
        sb.append("score=").append(score).append("/100\tverdict=").append(verdict)
                .append("\tpacker=").append(packer == null ? "none" : packer).append('\n');
        sb.append("indicator\tdetail\tweight\n");
        sb.append(rows);
        sb.append("# imports=").append(imports)
                .append(", max_code_entropy=").append("%.2f".formatted(maxCodeEntropy)).append('\n');
        return sb.toString();
    }

    private static void row(StringBuilder rows, String indicator, String detail, int weight) {
        rows.append(indicator).append('\t').append(Responses.cell(detail)).append('\t').append(weight).append('\n');
    }

    static String normalizeSection(String name) {
        var s = name.trim().toLowerCase(Locale.ROOT);
        if (s.startsWith(".")) s = s.substring(1);
        int u = s.lastIndexOf('_');
        if (u > 0 && u < s.length() - 1 && s.substring(u + 1).chars().allMatch(Character::isDigit)) {
            s = s.substring(0, u);
        }
        return s;
    }

    private static Map<String, String> packerSections() {
        var raw = new LinkedHashMap<String, String>();
        for (var n : new String[]{"upx0", "upx1", "upx2"}) raw.put(n, "UPX");
        for (var n : new String[]{".aspack", ".adata"}) raw.put(n, "ASPack");
        for (var n : new String[]{".nsp0", ".nsp1", ".nsp2"}) raw.put(n, "NsPack");
        for (var n : new String[]{".vmp0", ".vmp1", ".vmp2"}) raw.put(n, "VMProtect");
        raw.put(".petite", "Petite");
        raw.put(".mpress1", "MPRESS");
        raw.put(".mpress2", "MPRESS");
        raw.put("fsg!", "FSG");
        raw.put(".themida", "Themida");
        raw.put(".winlice", "Themida");
        raw.put(".enigma1", "Enigma");
        raw.put(".enigma2", "Enigma");
        raw.put(".y0da", "yoda");
        raw.put(".pec1", "PECompact");
        raw.put(".rlpack", "RLPack");
        raw.put(".packed", "generic");
        var m = new LinkedHashMap<String, String>();
        for (var e : raw.entrySet()) m.put(normalizeSection(e.getKey()), e.getValue());
        return m;
    }
}
