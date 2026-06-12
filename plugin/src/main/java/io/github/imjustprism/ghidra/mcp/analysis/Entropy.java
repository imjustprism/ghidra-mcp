package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;

public final class Entropy {

    private static final double INV_LOG2 = 1.0 / Math.log(2);

    private Entropy() {}

    public static double blockEntropy(MemoryBlock b) {
        if (!b.isInitialized() || b.getSize() == 0) return 0.0;
        int sample = (int) Math.min(b.getSize(), 65536L);
        var buf = new byte[sample];
        try {
            b.getBytes(b.getStart(), buf);
        } catch (Exception e) {
            return 0.0;
        }
        var counts = new long[256];
        for (var v : buf) counts[v & 0xFF]++;
        return shannon(counts, sample);
    }

    private static double shannon(long[] counts, int total) {
        double e = 0.0;
        for (var c : counts) {
            if (c == 0) continue;
            double prob = (double) c / total;
            e -= prob * (Math.log(prob) * INV_LOG2);
        }
        return e;
    }

    private record Hit(String addr, double entropy, int window) {}

    public static String highEntropyRegions(PluginContext ctx, double threshold, int window,
                                            Page p, Map<String, String> q) {
        if (window < 64 || window > 8192) throw new IllegalArgumentException("Window must be 64..8192");
        return ctx.withProgram(program -> {
            var memory = program.getMemory();
            var hits = new ConcurrentLinkedQueue<Hit>();
            try (var exec = Executors.newThreadPerTaskExecutor(
                    Thread.ofVirtual().name("entropy-", 0).factory())) {
                for (var block : memory.getBlocks()) {
                    if (!block.isInitialized()) continue;
                    exec.submit(() -> {
                        int cap = (int) Math.min(block.getSize(), 0x400000L);
                        var buf = new byte[cap];
                        try { memory.getBytes(block.getStart(), buf); } catch (Exception e) { Msg.trace(Entropy.class, "block read", e); return; }
                        int step = Math.max(window / 4, 64);
                        var counts = new int[256];
                        for (int i = 0; i + window <= buf.length; i += step) {
                            java.util.Arrays.fill(counts, 0);
                            for (int j = 0; j < window; j++) counts[buf[i + j] & 0xFF]++;
                            double e = 0.0;
                            for (var c : counts) {
                                if (c == 0) continue;
                                double prob = (double) c / window;
                                e -= prob * (Math.log(prob) * INV_LOG2);
                            }
                            if (e >= threshold) {
                                hits.add(new Hit(
                                        Responses.addr(block.getStart().add(i)), e, window));
                            }
                        }
                    });
                }
            }
            var t = Responses.table(p, q, new String[]{"addr", "entropy", "window"});
            var w = new Responses.Window(p);
            for (var h : hits) {
                if (!w.take()) continue;
                t.row(h.addr, "%.2f".formatted(h.entropy), h.window);
            }
            return t.total(w.total()).build();
        });
    }
}
