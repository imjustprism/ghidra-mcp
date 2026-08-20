package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Find defined data blobs whose length matches MD5/SHA-1/SHA-256/HMAC
 * digests — typical hardcoded expected hashes in license checks.
 */
public final class HashBlobs {

    private HashBlobs() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var rows = collect(program);
            var t = Responses.table(p, q, new String[]{"algo", "addr", "len", "hex", "xrefs"});
            var w = new Responses.Window(p);
            for (var r : rows) {
                if (!w.take()) continue;
                t.row(r.algo, r.addr, r.len, r.hex, r.xrefs);
            }
            return "# find_hash_blobs\n" + t.total(w.total()).build();
        });
    }

    static String classifyLen(int len) {
        return switch (len) {
            case 16 -> "md5/aes-key";
            case 20 -> "sha1";
            case 32 -> "sha256/aes-256";
            case 48 -> "sha384";
            case 64 -> "sha512";
            default -> "";
        };
    }

    static String toHex(byte[] b, int max) {
        int n = Math.min(b.length, max);
        var sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) sb.append(String.format(Locale.ROOT, "%02x", b[i] & 0xFF));
        if (b.length > max) sb.append("…");
        return sb.toString();
    }

    static boolean looksRandom(byte[] b) {
        if (b.length < 16) return false;
        int[] hist = new int[256];
        for (var x : b) hist[x & 0xFF]++;
        int max = 0;
        for (int h : hist) if (h > max) max = h;
        return max <= Math.max(3, b.length / 4);
    }

    private static List<Row> collect(Program program) {
        var out = new ArrayList<Row>();
        var listing = program.getListing();
        var rm = program.getReferenceManager();
        var it = listing.getDefinedData(true);
        while (it.hasNext()) {
            Data d = it.next();
            if (d == null) continue;
            int len = d.getLength();
            var algo = classifyLen(len);
            if (algo.isEmpty()) continue;
            byte[] raw;
            try {
                raw = d.getBytes();
            } catch (Exception e) {
                continue;
            }
            if (raw == null || !looksRandom(raw)) continue;
            int xrefs = 0;
            for (var ignored : rm.getReferencesTo(d.getAddress())) xrefs++;
            out.add(new Row(algo, Responses.addr(d.getAddress()), len, toHex(raw, 16), xrefs));
        }
        return out;
    }

    record Row(String algo, String addr, int len, String hex, int xrefs) {}
}
