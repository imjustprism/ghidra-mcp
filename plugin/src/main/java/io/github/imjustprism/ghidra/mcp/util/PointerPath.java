package io.github.imjustprism.ghidra.mcp.util;

public final class PointerPath {

    private PointerPath() {}

    public static long[] parseOffsets(String s) {
        if (s == null || s.isBlank()) return new long[0];
        var parts = s.split(",");
        var out = new long[parts.length];
        for (int i = 0; i < parts.length; i++) {
            var p = parts[i].trim();
            long sign = 1;
            if (p.startsWith("-")) {
                sign = -1;
                p = p.substring(1).trim();
            } else if (p.startsWith("+")) {
                p = p.substring(1).trim();
            }
            if (p.startsWith("0x") || p.startsWith("0X")) p = p.substring(2);
            if (p.isEmpty()) throw new IllegalArgumentException("empty offset in: " + s);
            out[i] = sign * Long.parseUnsignedLong(p, 16);
        }
        return out;
    }

    public static long toUnsignedLong(byte[] b, int len, boolean bigEndian) {
        if (b.length < len) throw new IllegalArgumentException("need " + len + " bytes, got " + b.length);
        long v = 0;
        if (bigEndian) {
            for (int i = 0; i < len; i++) v = (v << 8) | (b[i] & 0xFFL);
        } else {
            for (int i = len - 1; i >= 0; i--) v = (v << 8) | (b[i] & 0xFFL);
        }
        return v;
    }
}
