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
            var sig = PACKER_SECTIONS.get(block.getName().trim().toLowerCase(Locale.ROOT));
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
        for (var ignored : program.getSymbolTable().getExternalSymbols()) imports++;

        String oepBlock = null;
        var st = program.getSymbolTable();
        for (var it = st.getExternalEntryPointIterator(); it.hasNext() && oepBlock == null; ) {
            var block = program.getMemory().getBlock(it.next());
            if (block != null && block.isWrite()) oepBlock = block.getName();
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

    private static Map<String, String> packerSections() {
        var m = new LinkedHashMap<String, String>();
        for (var n : new String[]{"upx0", "upx1", "upx2"}) m.put(n, "UPX");
        for (var n : new String[]{".aspack", ".adata"}) m.put(n, "ASPack");
        for (var n : new String[]{".nsp0", ".nsp1", ".nsp2"}) m.put(n, "NsPack");
        for (var n : new String[]{".vmp0", ".vmp1", ".vmp2"}) m.put(n, "VMProtect");
        m.put(".petite", "Petite");
        m.put(".mpress1", "MPRESS");
        m.put(".mpress2", "MPRESS");
        m.put("fsg!", "FSG");
        m.put(".themida", "Themida");
        m.put(".winlice", "Themida");
        m.put(".enigma1", "Enigma");
        m.put(".enigma2", "Enigma");
        m.put(".y0da", "yoda");
        m.put(".pec1", "PECompact");
        m.put(".rlpack", "RLPack");
        m.put(".packed", "generic");
        return m;
    }
}
