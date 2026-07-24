package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class OrphanGaps {

    private OrphanGaps() {}

    public static String find(PluginContext ctx, int minSize, Map<String, String> q) {
        if (minSize < 1) throw new IllegalArgumentException("min_size must be >= 1");
        return ctx.withProgram(program -> {
            var listing = program.getListing();
            var fm = program.getFunctionManager();
            var t = Responses.table(q, new String[]{"start", "end", "size"}, 64);
            var w = new Responses.Window(Page.from(q));
            for (var block : program.getMemory().getBlocks()) {
                if (!block.isExecute() || !block.isInitialized()) continue;
                Address cur = block.getStart();
                Address endAddr = block.getEnd();
                Address gapStart = null;
                while (cur != null && cur.compareTo(endAddr) <= 0) {
                    var instr = listing.getInstructionAt(cur);
                    if (instr == null) { cur = cur.next(); continue; }
                    var containing = fm.getFunctionContaining(cur);
                    if (containing == null) {
                        if (gapStart == null) gapStart = cur;
                        var next = cur.add(instr.getLength());
                        if (next.compareTo(endAddr) > 0) next = endAddr;
                        cur = next;
                    } else {
                        if (gapStart != null) {
                            long size = cur.subtract(gapStart);
                            if (size >= minSize && w.take()) {
                                t.row(Responses.addr(gapStart), Responses.addr(cur), size);
                            }
                            gapStart = null;
                        }
                        cur = containing.getBody().getMaxAddress().next();
                    }
                }
                if (gapStart != null && cur != null) {
                    long size = cur.subtract(gapStart);
                    if (size >= minSize && w.take()) {
                        t.row(Responses.addr(gapStart), Responses.addr(cur), size);
                    }
                }
            }
            return t.total(w.total()).build();
        });
    }
}
