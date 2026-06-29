package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.mem.MemoryAccessException;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class VmDescriptor {

    private static final int HARD_CAP = 4096;

    private VmDescriptor() {}

    public static String parse(PluginContext ctx, String tableAddr, int maxEntries, Map<String, String> q) {
        if (tableAddr == null || tableAddr.isBlank()) {
            throw new IllegalArgumentException("table_address is required (the (call_site_RVA, dest_RVA)"
                    + " descriptor table; e.g. the Oreans CV table at engine_header+0x40)");
        }
        int cap = maxEntries <= 0 ? 256 : Math.min(maxEntries, HARD_CAP);
        return ctx.withProgram(program -> {
            var addr = program.getAddressFactory().getAddress(tableAddr.trim());
            if (addr == null) throw new IllegalArgumentException("invalid table_address: " + tableAddr);
            long base = program.getImageBase().getOffset();
            var mem = program.getMemory();
            var fm = program.getFunctionManager();
            var space = program.getAddressFactory().getDefaultAddressSpace();
            var t = Responses.table(q, new String[]{"i", "call_site", "function", "bytecode_dest"}, 16);
            int n = 0;
            try {
                for (int i = 0; i < cap; i++) {
                    var entry = addr.add((long) i * 8);
                    long callRva = mem.getInt(entry) & 0xffffffffL;
                    long destRva = mem.getInt(entry.add(4)) & 0xffffffffL;
                    if (callRva == 0 && destRva == 0) break;
                    var callAbs = space.getAddress(base + callRva);
                    var fn = fm.getFunctionContaining(callAbs);
                    t.row(i, Responses.addr(callAbs), fn == null ? "" : fn.getName(),
                            Responses.addr(space.getAddress(base + destRva)));
                    n++;
                }
            } catch (MemoryAccessException e) {
                throw new IllegalArgumentException("read past mapped memory at entry " + n + ": " + e.getMessage());
            }
            return "# vm descriptor table @ " + Responses.addr(addr) + " — " + n + " entr(y/ies)"
                    + " (each = call_site_RVA, bytecode_dest_RVA; +image base 0x"
                    + Long.toHexString(base) + ")\n" + t.total(n).build();
        });
    }
}
