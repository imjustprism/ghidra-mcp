package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;

public final class EncodedStrings {

    private EncodedStrings() {}

    private record Hit(int key, long offset, int len, String text) {}

    public static String find(PluginContext ctx, String addr, int length, int minLen,
                              Page p, Map<String, String> q) {
        if (addr == null || addr.isEmpty()) throw new IllegalArgumentException("Address is required");
        if (length <= 0 || length > 0x200000) throw new IllegalArgumentException("Length must be 1..2097152");
        if (minLen < 3) minLen = 3;
        final int ml = minLen;
        return ctx.withAddress(addr, (program, a) -> {
            var buf = new byte[length];
            try {
                program.getMemory().getBytes(a, buf, 0, length);
            } catch (Exception e) {
                return "Read error: " + e.getMessage();
            }
            var hits = new ConcurrentLinkedQueue<Hit>();
            try (var exec = Executors.newThreadPerTaskExecutor(
                    Thread.ofVirtual().name("xor-", 0).factory())) {
                for (int k = 1; k < 256; k++) {
                    final int key = k;
                    exec.submit(() -> scanKey(buf, key, ml, hits));
                }
            }
            var t = Responses.table(p, q, new String[]{"key", "off", "len", "value"});
            var w = new Responses.Window(p);
            for (var h : hits) {
                if (!w.take()) continue;
                t.row("%02x".formatted(h.key), "%x".formatted(h.offset), h.len,
                      Strings.escapeString(h.text));
            }
            return t.total(w.total()).build();
        });
    }

    private static void scanKey(byte[] buf, int key, int minLen, ConcurrentLinkedQueue<Hit> hits) {
        int run = 0, runStart = -1;
        for (int i = 0; i < buf.length; i++) {
            int b = (buf[i] ^ key) & 0xFF;
            boolean printable = (b >= 0x20 && b < 0x7F) || b == 0x09 || b == 0x0A || b == 0x0D;
            if (printable) {
                if (run == 0) runStart = i;
                run++;
            } else {
                if (run >= minLen) emit(buf, key, runStart, i, hits);
                run = 0;
            }
        }
        if (run >= minLen) emit(buf, key, runStart, buf.length, hits);
    }

    private static void emit(byte[] buf, int key, int start, int end, ConcurrentLinkedQueue<Hit> hits) {
        var sb = new StringBuilder(end - start);
        for (int j = start; j < end; j++) sb.append((char) ((buf[j] ^ key) & 0xFF));
        hits.add(new Hit(key, start, end - start, sb.toString()));
    }
}
