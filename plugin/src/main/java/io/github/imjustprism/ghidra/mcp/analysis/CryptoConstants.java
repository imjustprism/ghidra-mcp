package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.mem.Memory;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public final class CryptoConstants {

    private record Known(String name, byte[] bytes) {}

    private static final List<Known> SIGNATURES = List.of(
        new Known("aes_sbox", hex("637c777bf26b6fc53001672bfed7ab76")),
        new Known("aes_inv_sbox", hex("52096ad53036a538bf40a39e81f3d7fb")),
        new Known("aes_te0", hex("a56363c6847c7cf8997777ee8d7b7bff")),
        new Known("sha256_h", hex("67e6096a85ae67bb72f36e3c3af54fa5")),
        new Known("sha256_k", hex("982f8a4291443771cffbc0b5a5dbb5e9")),
        new Known("md5_k", hex("78a46ad756b7c7e8db702024eecebdc1")),
        new Known("md5_sha1_init", hex("0123456789abcdeffedcba9876543210"))
    );

    private CryptoConstants() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var mem = program.getMemory();
            var monitor = new ConsoleTaskMonitor();
            var t = Responses.table(p, q, new String[]{"addr", "algo", "len"});
            var w = new Responses.Window(p);
            for (var sig : SIGNATURES) {
                var mask = new byte[sig.bytes().length];
                Arrays.fill(mask, (byte) 0xFF);
                var cursor = mem.getMinAddress();
                while (cursor != null) {
                    var hit = mem.findBytes(cursor, sig.bytes(), mask, true, monitor);
                    if (hit == null) break;
                    if (w.take()) t.row(Responses.addr(hit), sig.name(), sig.bytes().length);
                    cursor = hit.next();
                }
            }
            return t.total(w.total()).build();
        });
    }

    private static byte[] hex(String s) {
        var out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
