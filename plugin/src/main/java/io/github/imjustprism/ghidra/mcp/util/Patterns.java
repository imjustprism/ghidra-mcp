package io.github.imjustprism.ghidra.mcp.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Patterns {

    private Patterns() {}

    private static final byte MATCH = (byte) 0xFF;
    private static final byte WILD = 0;
    private static final Pattern CODE_BYTE = Pattern.compile("\\\\x([0-9A-Fa-f]{2})");
    private static final Pattern MASK_TOKEN = Pattern.compile("[xX?.]+");

    public record Sig(byte[] bytes, byte[] mask) {
        public int length() {
            return bytes.length;
        }

        public int wildcards() {
            int c = 0;
            for (byte m : mask) {
                if (m == WILD) c++;
            }
            return c;
        }

        public boolean allWildcard() {
            return bytes.length == 0 || wildcards() == bytes.length;
        }

        public String ida() {
            var sb = new StringBuilder(bytes.length * 3);
            for (int i = 0; i < bytes.length; i++) {
                if (i > 0) sb.append(' ');
                if (mask[i] == WILD) sb.append("??");
                else sb.append("%02X".formatted(bytes[i] & 0xFF));
            }
            return sb.toString();
        }

        public String code() {
            var b = new StringBuilder(bytes.length * 4);
            var m = new StringBuilder(bytes.length);
            for (int i = 0; i < bytes.length; i++) {
                if (mask[i] == WILD) {
                    b.append("\\x00");
                    m.append('?');
                } else {
                    b.append("\\x%02X".formatted(bytes[i] & 0xFF));
                    m.append('x');
                }
            }
            return b + " " + m;
        }

        public String render(String format) {
            return "code".equalsIgnoreCase(format) ? code() : ida();
        }
    }

    public static Sig parse(String raw) {
        if (raw == null || raw.isBlank()) throw new IllegalArgumentException("empty pattern");
        var s = raw.trim();
        if (s.contains("\\x")) return parseCodeMask(s);
        var units = tokenize(s);
        var bytes = new byte[units.size()];
        var mask = new byte[units.size()];
        for (int i = 0; i < units.size(); i++) {
            var u = units.get(i);
            if (isWildcardUnit(u)) {
                mask[i] = WILD;
            } else if (u.length() == 2 && isHex(u)) {
                bytes[i] = (byte) Integer.parseInt(u, 16);
                mask[i] = MATCH;
            } else {
                throw new IllegalArgumentException("bad byte token: " + u);
            }
        }
        return new Sig(bytes, mask);
    }

    private static List<String> tokenize(String s) {
        var cleaned = s.replace(",", " ").trim();
        if (cleaned.indexOf(' ') < 0 && cleaned.indexOf('\t') < 0) return chunk(cleaned);
        var out = new ArrayList<String>();
        for (var tok : cleaned.split("\\s+")) {
            if (!tok.isEmpty()) out.add(tok);
        }
        return out;
    }

    private static List<String> chunk(String s) {
        if (s.length() % 2 != 0) throw new IllegalArgumentException("pattern must have even length");
        var out = new ArrayList<String>(s.length() / 2);
        for (int i = 0; i < s.length(); i += 2) out.add(s.substring(i, i + 2));
        return out;
    }

    private static boolean isWildcardUnit(String u) {
        for (int i = 0; i < u.length(); i++) {
            char c = u.charAt(i);
            if (c != '?' && c != '*') return false;
        }
        return !u.isEmpty();
    }

    private static boolean isHex(String u) {
        for (int i = 0; i < u.length(); i++) {
            if (Character.digit(u.charAt(i), 16) < 0) return false;
        }
        return true;
    }

    private static Sig parseCodeMask(String s) {
        var bytesList = new ArrayList<Byte>();
        Matcher mb = CODE_BYTE.matcher(s);
        while (mb.find()) bytesList.add((byte) Integer.parseInt(mb.group(1), 16));
        if (bytesList.isEmpty()) throw new IllegalArgumentException("no \\xHH bytes found");
        var tail = CODE_BYTE.matcher(s).replaceAll("").replace("\"", "").trim();
        Matcher mm = MASK_TOKEN.matcher(tail);
        String maskStr = null;
        while (mm.find()) {
            var g = mm.group();
            if (g.length() == bytesList.size()) {
                maskStr = g;
                break;
            }
        }
        var bytes = new byte[bytesList.size()];
        var mask = new byte[bytesList.size()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = bytesList.get(i);
            boolean wild = maskStr != null && (maskStr.charAt(i) == '?' || maskStr.charAt(i) == '.');
            mask[i] = wild ? WILD : MATCH;
        }
        return new Sig(bytes, mask);
    }

    public static long countMatches(Memory mem, Sig sig, long cap) {
        if (sig.allWildcard()) return cap;
        var monitor = new ConsoleTaskMonitor();
        Address cursor = mem.getMinAddress();
        long n = 0;
        while (cursor != null && n < cap) {
            Address hit = mem.findBytes(cursor, sig.bytes(), sig.mask(), true, monitor);
            if (hit == null) break;
            n++;
            cursor = hit.next();
        }
        return n;
    }
}
