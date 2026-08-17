package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public final class Unwind {

    public static final int ENTRY_SIZE = 12;

    public record Entry(long beginRva, long endRva, long unwindRva, Address at) {}

    private Unwind() {}

    public static MemoryBlock pdata(Program program) {
        for (var b : program.getMemory().getBlocks()) {
            if (".pdata".equalsIgnoreCase(b.getName())) return b;
        }
        return null;
    }

    public static boolean inPdata(Program program, Address a) {
        var b = pdata(program);
        return b != null && b.contains(a);
    }

    public static long rva(Program program, Address a) {
        return a.getOffset() - program.getImageBase().getOffset();
    }

    public static Entry entryAt(Program program, Address a) {
        var block = pdata(program);
        if (block == null || !block.contains(a)) return null;
        long slot = (a.getOffset() - block.getStart().getOffset()) / ENTRY_SIZE;
        return read(program, block, slot);
    }

    public static Entry covering(Program program, Address target) {
        var block = pdata(program);
        if (block == null) return null;
        long want = rva(program, target);
        long count = block.getSize() / ENTRY_SIZE;
        long lo = 0;
        long hi = count - 1;
        Entry best = null;
        while (lo <= hi) {
            long mid = (lo + hi) >>> 1;
            var e = read(program, block, mid);
            if (e == null) return null;
            if (e.beginRva() <= want) {
                best = e;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        if (best == null) return null;
        return want < best.endRva() ? best : null;
    }

    public static Address owner(Program program, Entry e) {
        if (e == null) return null;
        try {
            return program.getImageBase().add(e.beginRva());
        } catch (Exception ex) {
            return null;
        }
    }

    public static boolean isSelfUnwind(Program program, Address refFrom, Address funcEntry) {
        var e = entryAt(program, refFrom);
        return e != null && e.beginRva() == rva(program, funcEntry);
    }

    private static Entry read(Program program, MemoryBlock block, long slot) {
        if (slot < 0 || slot >= block.getSize() / ENTRY_SIZE) return null;
        var at = block.getStart().add(slot * ENTRY_SIZE);
        try {
            long begin = Integer.toUnsignedLong(program.getMemory().getInt(at));
            long end = Integer.toUnsignedLong(program.getMemory().getInt(at.add(4)));
            long unwind = Integer.toUnsignedLong(program.getMemory().getInt(at.add(8)));
            return new Entry(begin, end, unwind, at);
        } catch (Exception e) {
            return null;
        }
    }
}
