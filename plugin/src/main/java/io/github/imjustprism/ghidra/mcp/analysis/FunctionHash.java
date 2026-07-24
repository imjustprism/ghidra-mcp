package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class FunctionHash {

    private static final long FNV_OFFSET = 0xcbf29ce484222325L;
    private static final long FNV_PRIME = 0x100000001b3L;

    private FunctionHash() {}

    public static String hash(PluginContext ctx, String addr, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("No function at " + addr);
            var mnemonics = new StringBuilder();
            var shape = new StringBuilder();
            int count = 0;
            var it = program.getListing().getInstructions(func.getBody(), true);
            while (it.hasNext()) {
                var insn = it.next();
                var m = insn.getMnemonicString();
                mnemonics.append(m).append(';');
                shape.append(m).append(':').append(insn.getNumOperands()).append(';');
                count++;
            }
            var t = Responses.table(q, new String[]{"k", "v"}, 4);
            t.row("fn", func.getName());
            t.row("instructions", count);
            t.row("mnemonic_hash", "0x" + Long.toHexString(fnv1a(mnemonics)));
            t.row("shape_hash", "0x" + Long.toHexString(fnv1a(shape)));
            return t.build();
        });
    }

    public static long shapeHash(ghidra.program.model.listing.Program program,
            ghidra.program.model.listing.Function func) {
        var shape = new StringBuilder();
        var it = program.getListing().getInstructions(func.getBody(), true);
        while (it.hasNext()) {
            var insn = it.next();
            shape.append(insn.getMnemonicString()).append(':').append(insn.getNumOperands()).append(';');
        }
        return fnv1a(shape);
    }

    private static long fnv1a(CharSequence s) {
        long h = FNV_OFFSET;
        for (int i = 0; i < s.length(); i++) {
            h ^= s.charAt(i) & 0xff;
            h *= FNV_PRIME;
        }
        return h;
    }
}
