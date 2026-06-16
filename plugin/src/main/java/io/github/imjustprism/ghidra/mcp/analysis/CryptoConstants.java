package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public final class CryptoConstants {

    private static final int MAX_HITS_PER_SIG = 64;

    private record Sig(String name, byte[] bytes) {}

    private static final byte[] AES_SBOX = hex("637c777bf26b6fc53001672bfed7ab76");
    private static final byte[] AES_INV_SBOX = hex("52096ad53036a538bf40a39e81f3d7fb");

    private record WordTable(String name, int[] words) {}

    private static final List<WordTable> WORD_TABLES = List.of(
        new WordTable("aes_te0", new int[]{0xc66363a5, 0xf87c7c84, 0xee777799, 0xff7b7b8d}),
        new WordTable("sha256_h", new int[]{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a}),
        new WordTable("sha256_k", new int[]{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5}),
        new WordTable("md5_k", new int[]{0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee}),
        new WordTable("md5_sha1_init", new int[]{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}),
        new WordTable("crc32", new int[]{0x00000000, 0x77073096, 0xee0e612c, 0x990951ba})
    );

    private CryptoConstants() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var mem = program.getMemory();
            var monitor = new ConsoleTaskMonitor();
            var t = Responses.table(p, q, new String[]{"addr", "algo", "len"});
            var w = new Responses.Window(p);
            for (var sig : signatures(program)) {
                var mask = new byte[sig.bytes().length];
                Arrays.fill(mask, (byte) 0xFF);
                var cursor = mem.getMinAddress();
                int hits = 0;
                while (cursor != null && hits < MAX_HITS_PER_SIG) {
                    var hit = mem.findBytes(cursor, sig.bytes(), mask, true, monitor);
                    if (hit == null) break;
                    if (w.take()) t.row(Responses.addr(hit), sig.name(), sig.bytes().length);
                    hits++;
                    cursor = hit.next();
                }
            }
            return t.total(w.total()).build();
        });
    }

    private static List<Sig> signatures(Program program) {
        var big = program.getLanguage().isBigEndian();
        var sigs = new ArrayList<Sig>(2 + WORD_TABLES.size());
        sigs.add(new Sig("aes_sbox", AES_SBOX));
        sigs.add(new Sig("aes_inv_sbox", AES_INV_SBOX));
        for (var wt : WORD_TABLES) {
            sigs.add(new Sig(wt.name(), wordsToBytes(wt.words(), big)));
        }
        return sigs;
    }

    private static byte[] wordsToBytes(int[] words, boolean big) {
        var out = new byte[words.length * 4];
        for (int i = 0; i < words.length; i++) {
            int w = words[i];
            int base = i * 4;
            if (big) {
                out[base] = (byte) (w >>> 24);
                out[base + 1] = (byte) (w >>> 16);
                out[base + 2] = (byte) (w >>> 8);
                out[base + 3] = (byte) w;
            } else {
                out[base] = (byte) w;
                out[base + 1] = (byte) (w >>> 8);
                out[base + 2] = (byte) (w >>> 16);
                out[base + 3] = (byte) (w >>> 24);
            }
        }
        return out;
    }

    private static byte[] hex(String s) {
        var out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
