package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.LinkedHashSet;
import java.util.Map;

public final class RopGadgets {

    private static final int MAX_BACK = 16;
    private static final int SCAN_CAP = 0x400000;

    private RopGadgets() {}

    public static String find(PluginContext ctx, String filter, int maxInstrs, Page p, Map<String, String> q) {
        int maxIns = maxInstrs <= 0 ? 5 : Math.min(maxInstrs, 12);
        var needle = filter == null || filter.isBlank() ? null : filter.toLowerCase();
        return ctx.withProgram(program -> {
            var pdis = new PseudoDisassembler(program);
            var t = Responses.table(p, q, new String[]{"addr", "gadget"});
            var w = new Responses.Window(p);
            var seen = new LinkedHashSet<String>();
            int budget = p.offset() + p.limit();
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (!block.isExecute() || !block.isInitialized()) continue;
                int len = (int) Math.min(block.getSize(), SCAN_CAP);
                var bytes = new byte[len];
                try {
                    block.getBytes(block.getStart(), bytes);
                } catch (Exception e) {
                    continue;
                }
                for (int i = 0; i < len && w.total() < budget; i++) {
                    int b = bytes[i] & 0xff;
                    if (b != 0xc3 && b != 0xc2) continue;
                    var retAddr = block.getStart().add(i);
                    for (int back = 1; back <= MAX_BACK; back++) {
                        var gadget = build(pdis, block.getStart().add(i - back), retAddr, maxIns);
                        if (gadget == null) continue;
                        if (needle != null && !gadget.toLowerCase().contains(needle)) continue;
                        if (!seen.add(gadget)) continue;
                        if (w.take()) t.row(Responses.addr(block.getStart().add(i - back)), gadget);
                    }
                }
            }
            return t.total(w.total()).build();
        });
    }

    private static String build(PseudoDisassembler pdis, Address start, Address retAddr, int maxIns) {
        if (start.getOffset() >= retAddr.getOffset()) return null;
        var sb = new StringBuilder();
        var cur = start;
        for (int n = 0; n <= maxIns; n++) {
            if (cur.getOffset() > retAddr.getOffset()) return null;
            ghidra.program.model.listing.Instruction insn;
            try {
                insn = pdis.disassemble(cur);
            } catch (Exception e) {
                return null;
            }
            if (insn == null) return null;
            var mn = insn.getMnemonicString().toUpperCase();
            if (cur.equals(retAddr)) {
                sb.append(insn);
                return sb.toString();
            }
            if (isBoundary(mn)) return null;
            sb.append(insn).append("; ");
            cur = cur.add(insn.getLength());
        }
        return null;
    }

    private static boolean isBoundary(String mn) {
        return mn.startsWith("RET") || mn.startsWith("J") || mn.equals("CALL")
                || mn.startsWith("LOOP") || mn.equals("INT") || mn.equals("HLT");
    }
}
