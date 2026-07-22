package io.github.imjustprism.ghidra.mcp.util;

public final class LiveBases {

    private LiveBases() {}

    public static boolean isPseudo(String s) {
        if (s == null) return false;
        var t = s.trim();
        return t.regionMatches(true, 0, "tls:", 0, 4)
                || t.regionMatches(true, 0, "teb:", 0, 4)
                || t.equalsIgnoreCase("tls")
                || t.equalsIgnoreCase("teb");
    }

    public static long resolve(ProcessMemory rpm, int pid, String spec) {
        if (spec == null || spec.isBlank()) throw new IllegalArgumentException("address is required");
        var t = spec.trim();
        if (t.regionMatches(true, 0, "tls:", 0, 4) || t.equalsIgnoreCase("tls")) {
            long slot = t.equalsIgnoreCase("tls") ? 0 : parseSlot(t.substring(4).trim());
            return tlsAddress(rpm, pid, slot);
        }
        if (t.regionMatches(true, 0, "teb:", 0, 4) || t.equalsIgnoreCase("teb")) {
            long off = t.equalsIgnoreCase("teb") ? 0 : parseSlot(t.substring(4).trim());
            var hit = gameTls(rpm, pid);
            if (hit == null) throw new IllegalStateException("no TEB/TLS on any thread (need live game main thread)");
            return hit.teb() + off;
        }
        return parseAbs(t);
    }

    public static long tlsAddress(ProcessMemory rpm, int pid, long slot) {
        var hit = gameTls(rpm, pid);
        if (hit == null) {
            throw new IllegalStateException(
                    "could not resolve module TLS (no thread with non-null TLS+0x58). "
                            + "Is the game on the main thread / fully loaded?");
        }
        return hit.tlsBase() + slot;
    }

    public static ProcessMemory.TlsHit gameTls(ProcessMemory rpm, int pid) {
        var mods = rpm.modules(pid);
        long base = mods.isEmpty() ? 0 : mods.get(0).base();
        int idx = rpm.tlsIndex(pid, base);
        return rpm.findGameTls(pid, idx, 0x58);
    }

    private static long parseSlot(String s) {
        if (s.isEmpty()) return 0;
        if (s.startsWith("+")) s = s.substring(1);
        if (s.startsWith("0x") || s.startsWith("0X")) return Long.parseLong(s.substring(2), 16);
        if (s.chars().allMatch(Character::isDigit)) return Long.parseLong(s);
        return Long.parseLong(s, 16);
    }

    private static long parseAbs(String s) {
        var v = s.trim();
        boolean hex = v.startsWith("0x") || v.startsWith("0X");
        return Long.parseUnsignedLong(hex ? v.substring(2) : v, 16);
    }
}
