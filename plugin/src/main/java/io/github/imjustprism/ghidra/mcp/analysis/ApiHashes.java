package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.hashes.Hashes;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;

public final class ApiHashes {

    private ApiHashes() {}

    private record Hit(String addr, int value, String name) {}

    public static String find(PluginContext ctx, String algo, Page p, Map<String, String> q) {
        var which = algo == null ? "fnv1a" : algo.toLowerCase();
        return ctx.withProgram(program -> {
            var hashMap = new HashMap<Integer, String>();
            for (var name : Hashes.COMMON_APIS) {
                int h = switch (which) {
                    case "fnv1a", "fnv1a_upper" -> Hashes.fnv1a(name, true);
                    case "fnv1a_lower" -> Hashes.fnv1a(name, false);
                    case "djb2" -> Hashes.djb2(name);
                    case "crc32" -> Hashes.crc32(name);
                    default -> 0;
                };
                hashMap.put(h, name);
            }
            var memory = program.getMemory();
            var hits = new ConcurrentLinkedQueue<Hit>();
            try (var exec = Executors.newThreadPerTaskExecutor(
                    Thread.ofVirtual().name("apihash-", 0).factory())) {
                for (var block : memory.getBlocks()) {
                    if (!block.isInitialized() || !block.isExecute()) continue;
                    exec.submit(() -> {
                        int cap = (int) Math.min(block.getSize(), 0x400000L);
                        var buf = new byte[cap];
                        try { memory.getBytes(block.getStart(), buf); } catch (Exception e) { Msg.trace(ApiHashes.class, "block read", e); return; }
                        for (int i = 0; i + 4 <= buf.length; i++) {
                            int v = (buf[i] & 0xFF) | ((buf[i+1] & 0xFF) << 8)
                                  | ((buf[i+2] & 0xFF) << 16) | ((buf[i+3] & 0xFF) << 24);
                            var name = hashMap.get(v);
                            if (name != null) {
                                hits.add(new Hit(Responses.addr(block.getStart().add(i)), v, name));
                            }
                        }
                    });
                }
            }
            var t = Responses.table(p, q, new String[]{"addr", "hash", "name"});
            var w = new Responses.Window(p);
            for (var h : hits) {
                if (!w.take()) continue;
                t.row(h.addr, "%08x".formatted(h.value), h.name);
            }
            return t.total(w.total()).build();
        });
    }
}
