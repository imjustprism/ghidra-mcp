package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.mem.MemoryAccessException;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.Locale;
import java.util.Map;

/**
 * Apply a recovered keystream (SplitMix64 / rolling XOR / xor8) to a memory
 * range and return the plaintext. Pair with recover_hidden_strings' seed column.
 */
public final class DecodeKeystream {

    private DecodeKeystream() {}

    public static String decode(PluginContext ctx, String addr, int length, String seedStr, String algo,
                                int increment, Map<String, String> q) {
        if (addr == null || addr.isBlank()) throw new IllegalArgumentException("address is required");
        if (length <= 0 || length > 65536) throw new IllegalArgumentException("length must be 1..65536");
        String kind = algo == null || algo.isBlank() ? "splitmix" : algo.trim().toLowerCase(Locale.ROOT);
        long seed = parseU64(seedStr);
        return ctx.withAddress(addr, (program, a) -> {
            var buf = new byte[length];
            int got;
            try {
                got = program.getMemory().getBytes(a, buf);
            } catch (MemoryAccessException e) {
                throw new IllegalStateException("read failed: " + e.getMessage(), e);
            }
            if (got <= 0) throw new IllegalStateException("no bytes at " + addr);
            var slice = got == length ? buf : java.util.Arrays.copyOf(buf, got);
            byte[] plain = switch (kind) {
                case "rolling_xor", "xor_inc" -> HiddenStrings.decodeRollingXor(slice, (int) seed, increment);
                case "xor8", "xor" -> HiddenStrings.decodeRollingXor(slice, (int) seed, 0);
                default -> HiddenStrings.decodeSplitMix(slice, seed);
            };
            var text = HiddenStrings.longestPrintable(plain, 1);
            var hex = toHex(plain, Math.min(plain.length, 64));
            var t = Responses.table(q, new String[]{"k", "v"}, 6);
            t.row("addr", Responses.addr(a));
            t.row("algo", kind);
            t.row("seed", "0x" + Long.toHexString(seed));
            t.row("len", plain.length);
            t.row("ascii", Strings.escapeString(text));
            t.row("hex", hex);
            return t.build();
        });
    }

    static long parseU64(String s) {
        if (s == null || s.isBlank()) throw new IllegalArgumentException("seed is required (hex, e.g. 0xdeadaecb09bfb3e0)");
        var t = s.trim();
        if (t.startsWith("0x") || t.startsWith("0X")) t = t.substring(2);
        try {
            return Long.parseUnsignedLong(t, 16);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("seed must be hex: " + s);
        }
    }

    static String toHex(byte[] b, int n) {
        var sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) sb.append(String.format(Locale.ROOT, "%02x", b[i] & 0xFF));
        return sb.toString();
    }
}
