package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.PointerPath;
import io.github.imjustprism.ghidra.mcp.util.Responses;

public final class PointerScan {

    private static final long CHUNK = 0x400000L;
    private static final long SCAN_BUDGET = 256L * 1024 * 1024;
    private static final int MAX_OFFSET = 0x4000;
    private static final int MAX_RESULTS = 1000;

    private PointerScan() {}

    public static String scan(PluginContext ctx, String targetStr, int maxOffset, int limit) {
        if (targetStr == null || targetStr.isBlank()) throw new IllegalArgumentException("target is required");
        int off = Math.min(Math.max(maxOffset, 0), MAX_OFFSET);
        int cap = Math.min(Math.max(limit, 1), MAX_RESULTS);
        return ctx.withProgram(program -> {
            var target = program.getAddressFactory().getAddress(targetStr);
            if (target == null) throw new IllegalArgumentException("invalid target address: " + targetStr);
            var space = target.getAddressSpace();
            int ptr = space.getPointerSize();
            if (ptr <= 0 || ptr > 8) {
                throw new IllegalArgumentException("unsupported pointer size for target space: " + ptr);
            }
            boolean bigEndian = program.getLanguage().isBigEndian();
            long targetOff = target.getOffset();
            long lo = Long.compareUnsigned(targetOff, off) < 0 ? 0 : targetOff - off;

            var memory = program.getMemory();
            var sb = new StringBuilder();
            sb.append("# pointer_scan target=").append(Responses.addr(target))
                    .append(" max_offset=0x").append(Long.toHexString(off))
                    .append(" ptr=").append(ptr).append('\n');
            sb.append("base\toffset\tvalue\n");

            int found = 0;
            long scanned = 0;
            boolean truncated = false;
            for (var block : memory.getBlocks()) {
                if (!block.isInitialized() || !block.getStart().getAddressSpace().equals(space)) continue;
                long size = block.getSize();
                long pos = Math.floorMod(-block.getStart().getOffset(), ptr);
                while (pos + ptr <= size) {
                    long remaining = SCAN_BUDGET - scanned;
                    if (remaining < ptr) { truncated = true; break; }
                    long want = Math.min(size - pos, Math.min(CHUNK, remaining));
                    if (pos + want < size) want -= want % ptr;
                    if (want < ptr) { truncated = true; break; }
                    int chunkLen = (int) want;
                    var buf = new byte[chunkLen];
                    try {
                        memory.getBytes(block.getStart().add(pos), buf);
                    } catch (Exception e) {
                        break;
                    }
                    scanned += chunkLen;
                    for (int i = 0; i + ptr <= chunkLen; i += ptr) {
                        long v = PointerPath.toUnsignedLong(buf, i, ptr, bigEndian);
                        if (Long.compareUnsigned(v, lo) >= 0 && Long.compareUnsigned(v, targetOff) <= 0) {
                            var holder = block.getStart().add(pos + i);
                            sb.append(Responses.addr(holder)).append("\t0x").append(Long.toHexString(targetOff - v))
                                    .append("\t0x").append(Long.toHexString(v)).append('\n');
                            if (++found >= cap) { truncated = true; break; }
                        }
                    }
                    if (found >= cap) break;
                    pos += chunkLen;
                }
                if (found >= cap || truncated) break;
            }
            sb.append("# ").append(found).append(" result(s)");
            if (truncated) sb.append(found >= cap ? ", capped at " + cap : ", scan budget reached");
            sb.append(". Each row is a base address + offset that reaches the target.\n");
            return sb.toString();
        });
    }
}
