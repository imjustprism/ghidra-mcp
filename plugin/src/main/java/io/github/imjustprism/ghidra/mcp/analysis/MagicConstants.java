package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class MagicConstants {

    private static final Map<Long, String> KNOWN = Map.ofEntries(
            Map.entry(0x6a09e667L, "SHA-256 H0"),
            Map.entry(0xbb67ae85L, "SHA-256 H1"),
            Map.entry(0x428a2f98L, "SHA-256 K0"),
            Map.entry(0x67452301L, "MD5/SHA-1 A init"),
            Map.entry(0xefcdab89L, "MD5/SHA-1 B init"),
            Map.entry(0x98badcfeL, "MD5/SHA-1 C init"),
            Map.entry(0x10325476L, "MD5/SHA-1 D init"),
            Map.entry(0xc3d2e1f0L, "SHA-1 E init"),
            Map.entry(0xd76aa478L, "MD5 K[0]"),
            Map.entry(0x5a827999L, "SHA-1 round K1"),
            Map.entry(0x6ed9eba1L, "SHA-1 round K2"),
            Map.entry(0x8f1bbcdcL, "SHA-1 round K3"),
            Map.entry(0xca62c1d6L, "SHA-1 round K4"),
            Map.entry(0x9e3779b9L, "golden ratio (TEA delta / hash mix)"),
            Map.entry(0x9E3779B97F4A7C15L, "SplitMix64 golden / string-xor increment"),
            Map.entry(0xBF58476D1CE4E5B9L, "SplitMix64 mixer #1 (string decrypt)"),
            Map.entry(0x94D049BB133111EBL, "SplitMix64 mixer #2 (string decrypt)"),
            Map.entry(0x811c9dc5L, "FNV-1 32 offset basis"),
            Map.entry(0x01000193L, "FNV-1 32 prime"),
            Map.entry(0xedb88320L, "CRC-32 reversed poly"),
            Map.entry(0x04c11db7L, "CRC-32 poly"),
            Map.entry(0xdeadbeefL, "marker 0xDEADBEEF"),
            Map.entry(0xcafebabeL, "marker 0xCAFEBABE"),
            Map.entry(0xccccccccL, "MSVC uninit-stack fill"),
            Map.entry(0xfeeefeeeL, "MSVC freed-heap fill"),
            Map.entry(0xbaadf00dL, "MSVC uninit-heap fill"));

    private MagicConstants() {}

    static String classify(long v) {
        if (v == 0x80000000L) return "f32 sign/neg mask";
        if (v == 0x7fffffffL) return "f32 abs mask";
        if (v == 0x8000000000000000L) return "f64 sign/neg mask";
        if (v == 0x7fffffffffffffffL) return "f64 abs mask";
        var known = KNOWN.get(v);
        if (known != null) return known;
        var d = IdiomSimplifier.recoverDivisor(v);
        return d != null ? "udiv-by-" + d + " magic" : "";
    }

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        long min = parseLong(q.get("min"), 0x100L);
        long max = parseLong(q.get("max"), 0xffffffffL);
        return ctx.withProgram(program -> run(program, min, max, p, q));
    }

    private static String run(Program program, long min, long max, Page p, Map<String, String> q) {
        var t = Responses.table(p, q, new String[]{"addr", "func", "instr", "value", "dec", "meaning"});
        var w = new Responses.Window(p);
        var listing = program.getListing();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!block.isExecute()) continue;
            Address cur = block.getStart();
            Address end = block.getEnd();
            var it = listing.getInstructions(cur, true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                if (ins.getAddress().compareTo(end) > 0) break;
                String mn = ins.getMnemonicString().toUpperCase();
                if (!isInteresting(mn)) continue;
                for (int i = 0; i < ins.getNumOperands(); i++) {
                    var objs = ins.getOpObjects(i);
                    if (objs == null) continue;
                    for (var o : objs) {
                        if (!(o instanceof Scalar s)) continue;
                        long v = s.getUnsignedValue();
                        String meaning = classify(v);
                        boolean known = !meaning.isEmpty();
                        if (!known) {
                            if (Long.compareUnsigned(v, min) < 0 || Long.compareUnsigned(v, max) > 0) continue;
                            if (isUninteresting(v)) continue;
                        }
                        if (!w.take()) continue;
                        Function f = program.getFunctionManager().getFunctionContaining(ins.getAddress());
                        String fname = f == null ? "" : f.getName();
                        t.row(Responses.addr(ins.getAddress()), fname, ins.toString(),
                              "0x" + Long.toHexString(v), v, meaning);
                    }
                }
            }
        }
        return t.total(w.total()).build();
    }

    private static boolean isInteresting(String mn) {
        return switch (mn) {
            case "CMP", "MOV", "ADD", "SUB", "XOR", "AND", "OR",
                 "IMUL", "MUL", "TEST", "LEA", "SHL", "SHR", "SAR",
                 "ROL", "ROR", "PUSH" -> true;
            default -> false;
        };
    }

    private static boolean isUninteresting(long v) {
        if (v == 0 || v == 1 || v == 2 || v == 3 || v == 4 || v == 8
                || v == 16 || v == 32 || v == 64 || v == 128 || v == 256) return true;
        if (v == 0xff || v == 0xffff || v == 0xffffff || v == 0xffffffffL) return true;
        return false;
    }

    private static long parseLong(String s, long def) {
        if (s == null || s.isEmpty()) return def;
        try {
            String t = s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s;
            int radix = s.startsWith("0x") || s.startsWith("0X") ? 16 : 10;
            return Long.parseLong(t, radix);
        } catch (NumberFormatException e) {
            Msg.trace(MagicConstants.class, "min/max parse", e);
            return def;
        }
    }
}
