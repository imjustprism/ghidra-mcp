package io.github.imjustprism.ghidra.mcp.util;

public final class Strings {

    private Strings() {}

    public static boolean isPrintable(int b) {
        return (b >= 0x20 && b < 0x7F) || b == 0x09 || b == 0x0A || b == 0x0D;
    }

    public static String escapeAscii(String s) {
        if (s == null) return "";
        var sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 32 && c < 127) sb.append(c);
            else sb.append("\\x").append(Integer.toHexString(c & 0xFF));
        }
        return sb.toString();
    }

    public static String escapeString(String s) {
        if (s == null) return "";
        var sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c >= 32 && c < 127) sb.append(c);
                    else sb.append("\\x%02x".formatted(c & 0xFF));
                }
            }
        }
        return sb.toString();
    }
}
