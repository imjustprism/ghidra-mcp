package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.math.BigInteger;
import java.util.Map;

public final class IdiomSimplifier {

    private IdiomSimplifier() {}

    public static String run(PluginContext ctx, String addr, Map<String, String> q) {
        boolean apply = "1".equals(q.get("apply"));
        return ctx.withAddress(addr, (program, a) -> {
            Function f = Addresses.functionAtOrContaining(program, a);
            if (f == null) throw new IllegalArgumentException("No function at or containing " + addr);
            var matches = scan(program, f);
            if (apply) {
                ctx.runOnSwingTx(program, "Idiom simplifier comments", () -> {
                    for (Match m : matches) {
                        program.getListing().setComment(m.at, CodeUnit.EOL_COMMENT, m.note);
                    }
                    return true;
                });
            }
            var t = Responses.table(q, new String[]{"addr", "idiom", "note"}, matches.size());
            for (Match m : matches) t.row(Responses.addr(m.at), m.kind, m.note);
            return t.total(matches.size()).build();
        });
    }

    private static java.util.List<Match> scan(Program program, Function f) {
        var out = new java.util.ArrayList<Match>();
        var listing = program.getListing();
        Address end = f.getBody().getMaxAddress();
        var it = listing.getInstructions(f.getEntryPoint(), true);
        Instruction[] window = new Instruction[8];
        int w = 0;
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins.getAddress().compareTo(end) > 0) break;
            window[w++ % window.length] = ins;
            tryUdivMagic(ins, listing, out);
            trySignExtDrop(ins, out);
            tryModFold(window, out);
        }
        return out;
    }

    private static void tryUdivMagic(Instruction ins, ghidra.program.model.listing.Listing l, java.util.List<Match> out) {
        String mn = ins.getMnemonicString().toUpperCase();
        if (!mn.equals("MOV")) return;
        if (ins.getNumOperands() < 2) return;
        var objs = ins.getOpObjects(1);
        if (objs == null || objs.length != 1 || !(objs[0] instanceof Scalar s)) return;
        long v = s.getUnsignedValue();
        if (v < 0x8000_0000L) return;
        Integer d = recoverDivisor(v);
        if (d == null) return;
        out.add(new Match(ins.getAddress(), "udiv_magic",
            "idiom: udiv by " + d + " (magic 0x" + Long.toHexString(v) + ")"));
    }

    private static Integer recoverDivisor(long magic) {
        BigInteger m = BigInteger.valueOf(magic);
        if (m.signum() <= 0) return null;
        for (int shift : new int[]{64, 65, 66, 67, 68, 69, 70, 71, 72}) {
            BigInteger twoN = BigInteger.ONE.shiftLeft(shift);
            for (int d = 3; d <= 255; d++) {
                if (d == 1 || (d & (d - 1)) == 0) continue;
                BigInteger bd = BigInteger.valueOf(d);
                // compiler's unsigned-divide magic: ceil(2^shift / d)
                BigInteger expected = twoN.add(bd).subtract(BigInteger.ONE).divide(bd);
                if (expected.equals(m)) return d;
            }
        }
        return null;
    }

    private static void trySignExtDrop(Instruction ins, java.util.List<Match> out) {
        String mn = ins.getMnemonicString().toUpperCase();
        if (!mn.equals("MOVSXD") && !mn.equals("MOVSX")) return;
        out.add(new Match(ins.getAddress(), "signext_drop",
            "idiom: sign-ext drop (dest later used 32-bit only)"));
    }

    private static void tryModFold(Instruction[] w, java.util.List<Match> out) {
        Instruction last = null, prev = null;
        int n = w.length;
        for (int i = 1; i <= n; i++) {
            Instruction c = w[(n - i) % n];
            if (c == null) break;
            if (last == null) { last = c; continue; }
            if (prev == null) { prev = c; break; }
        }
        if (last == null || prev == null) return;
        String lm = last.getMnemonicString().toUpperCase();
        String pm = prev.getMnemonicString().toUpperCase();
        if (!lm.equals("SUB")) return;
        if (!pm.equals("IMUL")) return;
        if (prev.getNumOperands() < 3) return;
        var objs = prev.getOpObjects(2);
        if (objs == null || objs.length != 1 || !(objs[0] instanceof Scalar s)) return;
        long k = s.getUnsignedValue();
        if (k < 2 || k > 0xffff) return;
        out.add(new Match(last.getAddress(), "mod_fold",
            "idiom: x %% " + k + " (x - " + k + "*(x/" + k + "))"));
    }

    private record Match(Address at, String kind, String note) {}
}
