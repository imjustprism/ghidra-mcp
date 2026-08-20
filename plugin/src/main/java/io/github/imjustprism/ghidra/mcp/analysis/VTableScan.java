package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;

public final class VTableScan {

    private VTableScan() {}

    private record Hit(String startAddr, int size, long firstFunc, int count, String className) {}

    /**
     * One recovered vtable: where it starts and the function addresses it holds,
     * in slot order. Callers that need slot indices (see {@code SdkExport}) want
     * the entries, not the rendered row.
     */
    public record Table(Address start, java.util.List<Address> entries) {}

    /**
     * Every pointer run that looks like a vtable, with its entries.
     *
     * <p>Shares the scan with {@link #scan} so there is one definition of what
     * counts as a vtable.
     */
    public static java.util.List<Table> tables(Program program) {
        var out = new ConcurrentLinkedQueue<Table>();
        forEachRun(program, (start, entries) -> out.add(new Table(start, entries)));
        var list = new java.util.ArrayList<>(out);
        list.sort(java.util.Comparator.comparing(Table::start));
        return list;
    }

    public static String scan(PluginContext ctx, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var hits = new ConcurrentLinkedQueue<Hit>();
            forEachRun(program, (start, entries) -> hits.add(new Hit(
                    Responses.addr(start), entries.size() * program.getDefaultPointerSize(),
                    entries.get(0).getOffset(), entries.size(), classAt(program, start))));
            var t = Responses.table(q, new String[]{"addr", "size", "first_func", "count", "class"}, hits.size());
            var w = new Responses.Window(Page.from(q));
            for (var h : hits) {
                if (!w.take()) continue;
                t.row(h.startAddr, h.size, "%x".formatted(h.firstFunc), h.count, h.className);
            }
            return t.total(w.total()).build();
        });
    }

    /** Receives each recovered run as (start, entries in slot order). */
    private interface RunSink {
        void accept(Address start, java.util.List<Address> entries);
    }

    /** Drive the vtable scan over every candidate data block, in parallel. */
    private static void forEachRun(Program program, RunSink sink) {
        var memory = program.getMemory();
        var fm = program.getFunctionManager();
        int ptrSize = program.getDefaultPointerSize();
        boolean le = !program.getLanguage().isBigEndian();
        try (var exec = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual().name("vtable-", 0).factory())) {
            for (var block : memory.getBlocks()) {
                if (!block.isInitialized() || block.isExecute()) continue;
                var bname = block.getName();
                if (bname == null) continue;
                var lower = bname.toLowerCase();
                // .pdata/.xdata match a bare "data" test but hold RUNTIME_FUNCTION
                // RVAs, not pointers — scanning them only invites false runs.
                if (lower.contains("pdata") || lower.contains("xdata")) continue;
                if (!(lower.contains("rdata") || lower.contains("data.rel.ro")
                        || lower.contains("const") || lower.contains("data"))) continue;
                exec.submit(() -> scanBlock(program, fm, block, ptrSize, le, sink));
            }
        }
    }

    private static void scanBlock(Program program, ghidra.program.model.listing.FunctionManager fm,
                                  ghidra.program.model.mem.MemoryBlock block, int ptrSize, boolean le,
                                  RunSink sink) {
        int cap = (int) Math.min(block.getSize(), 0x400000L);
        var buf = new byte[cap];
        try { program.getMemory().getBytes(block.getStart(), buf); } catch (Exception e) { Msg.trace(VTableScan.class, "block read", e); return; }
        var space = program.getAddressFactory().getDefaultAddressSpace();
        int i = 0;
        while (i + ptrSize <= buf.length) {
            long first = readPtr(buf, i, ptrSize, le);
            if (first == 0) { i += ptrSize; continue; }
            Address ptrAddr;
            try { ptrAddr = space.getAddress(first); } catch (Exception e) { Msg.trace(VTableScan.class, "ptr addr decode", e); i += ptrSize; continue; }
            if (fm.getFunctionAt(ptrAddr) == null) { i += ptrSize; continue; }
            var entries = new java.util.ArrayList<Address>();
            entries.add(ptrAddr);
            Address startAddr = block.getStart().add(i);
            int j = i + ptrSize;
            while (j + ptrSize <= buf.length) {
                long pv = readPtr(buf, j, ptrSize, le);
                if (pv == 0) break;
                Address pa;
                try { pa = space.getAddress(pv); } catch (Exception e) { Msg.trace(VTableScan.class, "ptr addr decode", e); break; }
                if (fm.getFunctionAt(pa) == null) break;
                entries.add(pa);
                j += ptrSize;
            }
            if (entries.size() >= 3) {
                sink.accept(startAddr, entries);
                i = j;
            } else {
                i += ptrSize;
            }
        }
    }

    private static String classAt(Program program, Address vtable) {
        var sym = program.getSymbolTable().getPrimarySymbol(vtable);
        if (sym == null) return "";
        var ns = sym.getParentNamespace();
        return ns != null && !ns.isGlobal() ? ns.getName(true) : "";
    }

    private static long readPtr(byte[] buf, int off, int size, boolean le) {
        long v = 0;
        if (le) {
            for (int k = size - 1; k >= 0; k--) v = (v << 8) | (buf[off + k] & 0xFFL);
        } else {
            for (int k = 0; k < size; k++) v = (v << 8) | (buf[off + k] & 0xFFL);
        }
        return v;
    }
}
