package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Locale;
import java.util.Map;

public final class DecodeStrings {

    private static final int MAX_LEN = 4096;
    private static final int PREVIEW_LEN = 80;
    private static final String[] SCHEMES = {"xor", "add", "sub"};

    private record Candidate(String scheme, int key, double printable, String preview) {}

    private DecodeStrings() {}

    public static String decode(PluginContext ctx, String addr, int length, double minPrintable,
                                int max, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            int len = Math.max(1, Math.min(length, MAX_LEN));
            var buf = new byte[len];
            int read;
            try {
                read = program.getMemory().getBytes(a, buf, 0, len);
            } catch (Exception e) {
                throw new IllegalStateException("read failed at " + addr + ": " + e.getMessage());
            }
            if (read <= 0) throw new IllegalStateException("no readable bytes at " + addr);

            var candidates = new ArrayList<Candidate>();
            for (int key = 1; key < 256; key++) {
                for (int op = 0; op < SCHEMES.length; op++) {
                    var decoded = apply(op, key, buf, read);
                    double ratio = printableRatio(decoded);
                    if (ratio >= minPrintable) {
                        candidates.add(new Candidate(SCHEMES[op], key, ratio, preview(decoded)));
                    }
                }
            }
            candidates.sort(Comparator.comparingDouble(Candidate::printable).reversed());
            int limit = Math.min(Math.max(1, max), candidates.size());

            var t = Responses.table(q, new String[]{"scheme", "key", "printable", "preview"}, limit);
            for (int i = 0; i < limit; i++) {
                var c = candidates.get(i);
                t.row(c.scheme(), "0x" + Integer.toHexString(c.key()),
                        String.format(Locale.ROOT, "%.2f", c.printable()), c.preview());
            }
            return t.total(candidates.size()).build();
        });
    }

    private static byte[] apply(int op, int key, byte[] buf, int read) {
        var out = new byte[read];
        for (int i = 0; i < read; i++) {
            int b = buf[i] & 0xFF;
            out[i] = (byte) switch (op) {
                case 0 -> b ^ key;
                case 1 -> (b + key) & 0xFF;
                default -> (b - key) & 0xFF;
            };
        }
        return out;
    }

    private static double printableRatio(byte[] bytes) {
        if (bytes.length == 0) return 0;
        int printable = 0;
        for (var b : bytes) {
            int c = b & 0xFF;
            if (c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e)) printable++;
        }
        return (double) printable / bytes.length;
    }

    private static String preview(byte[] bytes) {
        int n = Math.min(bytes.length, PREVIEW_LEN);
        var sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            int c = bytes[i] & 0xFF;
            sb.append(c >= 0x20 && c <= 0x7e ? (char) c : '.');
        }
        return Strings.escapeString(sb.toString());
    }
}
