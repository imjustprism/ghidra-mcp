package io.github.imjustprism.ghidra.mcp.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

public final class Bufs {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Bufs() {}

    public static byte[] read(Memory memory, Address addr, int length) throws Exception {
        var buf = new byte[length];
        int n = memory.getBytes(addr, buf, 0, length);
        if (n == length) return buf;
        var out = new byte[n];
        System.arraycopy(buf, 0, out, 0, n);
        return out;
    }

    public static String hex(byte[] bytes, int length) {
        var out = new char[length * 2];
        for (int i = 0; i < length; i++) {
            int b = bytes[i] & 0xFF;
            out[i * 2] = HEX[b >>> 4];
            out[i * 2 + 1] = HEX[b & 0xF];
        }
        return new String(out);
    }

    public static String hex(byte[] bytes) { return hex(bytes, bytes.length); }

    public static byte[] parseHex(String hex) {
        var normalized = hex.replace(" ", "").toUpperCase();
        if (normalized.length() % 2 != 0) throw new IllegalArgumentException("even length");
        var bytes = new byte[normalized.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(normalized.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
