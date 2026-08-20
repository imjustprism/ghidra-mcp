package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * FLOSS-style static recovery of obfuscated strings without running the sample.
 * Handles SplitMix64 keystream XOR (MortisEngine / similar), rolling XOR, and
 * contiguous MOV-imm byte stores (GET/POST/"1.1.0").
 */
public final class HiddenStrings {

    static final long GOLDEN = 0x9E3779B97F4A7C15L;
    static final long MULT1 = 0xBF58476D1CE4E5B9L;
    static final long MULT2 = 0x94D049BB133111EBL;

    private static final int MAX_BLOB = 256;
    private static final int LOOKBACK = 64;
    private static final double MIN_PRINTABLE = 0.78;
    private static final int MAX_FUNCTIONS = 8000;

    public record Hit(String algo, String func, String loop, String blob, int len, String seed,
                      String value) {}

    private HiddenStrings() {}

    public static String recover(PluginContext ctx, String addr, String algo, int minLen, boolean apply,
                                 Page p, Map<String, String> q) {
        int min = Math.min(Math.max(minLen, 3), 64);
        String want = algo == null || algo.isBlank() ? "auto" : algo.trim().toLowerCase(Locale.ROOT);
        return ctx.withProgram(program -> {
            List<Hit> hits;
            if (addr != null && !addr.isBlank()) {
                var a = Addresses.resolve(program, addr);
                if (a == null) throw new IllegalArgumentException("invalid address: " + addr);
                var func = Addresses.functionAtOrContaining(program, a);
                if (func == null) throw new IllegalArgumentException("no function at " + addr);
                hits = scanFunction(program, func, want, min);
            } else {
                hits = scanProgram(program, want, min);
            }
            if (apply && !hits.isEmpty()) {
                ctx.runOnSwingTx(program, "Recover hidden strings", () -> {
                    var listing = program.getListing();
                    for (var h : hits) {
                        if (h.loop().isEmpty()) continue;
                        var at = program.getAddressFactory().getAddress(h.loop());
                        if (at == null) at = program.getAddressFactory().getAddress("0x" + h.loop());
                        if (at == null) continue;
                        var note = h.algo() + ": " + h.value();
                        if (note.length() > 120) note = note.substring(0, 117) + "...";
                        listing.setComment(at, CodeUnit.EOL_COMMENT, note);
                    }
                    return true;
                });
            }
            var t = Responses.table(p, q, new String[]{"algo", "func", "loop", "blob", "len", "seed", "value"});
            var w = new Responses.Window(p);
            for (var h : hits) {
                if (!w.take()) continue;
                t.row(h.algo(), h.func(), h.loop(), h.blob(), h.len(), h.seed(),
                        Strings.escapeString(h.value()));
            }
            return "# recover_hidden_strings algo=" + want + " min_len=" + min
                    + (apply ? " apply=1" : "") + "\n" + t.total(w.total()).build();
        });
    }

    static List<Hit> scanProgram(Program program, String algo, int minLen) {
        var out = new ArrayList<Hit>();
        var seen = new LinkedHashSet<String>();
        int n = 0;
        for (var f : program.getFunctionManager().getFunctions(true)) {
            if (f.isThunk() || f.isExternal()) continue;
            if (n++ >= MAX_FUNCTIONS) break;
            for (var h : scanFunction(program, f, algo, minLen)) {
                if (seen.add(h.func() + "|" + h.value())) out.add(h);
            }
        }
        return out;
    }

    static List<Hit> scanFunction(Program program, Function func, String algo, int minLen) {
        var listing = program.getListing();
        var insns = new ArrayList<Instruction>();
        var it = listing.getInstructions(func.getBody(), true);
        while (it.hasNext()) insns.add(it.next());
        if (insns.isEmpty()) return List.of();

        var immediates = new ArrayList<Long>();
        var dataAddrs = new ArrayList<Address>();
        boolean splitmix = false;
        for (var ins : insns) {
            collectScalars(ins, immediates);
            var da = dataAddress(ins, program);
            if (da != null) dataAddrs.add(da);
            if (isSplitMixConst(immediates.isEmpty() ? 0 : immediates.get(immediates.size() - 1))) {
                splitmix = true;
            }
        }
        for (var v : immediates) {
            if (isSplitMixConst(v)) { splitmix = true; break; }
        }

        var hits = new ArrayList<Hit>();
        boolean wantMix = "auto".equals(algo) || "splitmix".equals(algo) || "all".equals(algo);
        boolean wantRoll = "auto".equals(algo) || "rolling_xor".equals(algo) || "xor".equals(algo)
                || "all".equals(algo);
        boolean wantImm = "auto".equals(algo) || "imm".equals(algo) || "stores".equals(algo)
                || "all".equals(algo);

        if (wantMix && splitmix) {
            recoverSplitMix(program, func, insns, immediates, dataAddrs, minLen, hits);
        }
        if (wantRoll) {
            recoverRollingXor(program, func, insns, minLen, hits);
        }
        if (wantImm) {
            recoverImmStores(func, insns, minLen, hits);
        }
        return hits;
    }

    static byte[] decodeSplitMix(byte[] blob, long seed) {
        var out = new byte[blob.length];
        long x = 0;
        for (int i = 0; i < blob.length; i++) {
            long v = x ^ seed;
            v = (v >>> 30 ^ v) * MULT1;
            v = (v >>> 27 ^ v) * MULT2;
            out[i] = (byte) (((v >>> 31) ^ v ^ (blob[i] & 0xFF)) & 0xFF);
            x += GOLDEN;
        }
        return out;
    }

    static byte[] decodeRollingXor(byte[] blob, int startKey, int increment) {
        var out = new byte[blob.length];
        int k = startKey & 0xFF;
        int inc = increment & 0xFF;
        for (int i = 0; i < blob.length; i++) {
            out[i] = (byte) ((blob[i] & 0xFF) ^ k);
            k = (k + inc) & 0xFF;
        }
        return out;
    }

    static String longestPrintable(byte[] decoded, int minLen) {
        int end = 0;
        for (; end < decoded.length; end++) {
            int b = decoded[end] & 0xFF;
            if (b == 0) break;
            if (!Strings.isPrintable(b)) {
                if (end >= minLen) break;
                return "";
            }
        }
        if (end < minLen) return "";
        int printable = 0;
        for (int i = 0; i < end; i++) {
            if (Strings.isPrintable(decoded[i] & 0xFF)) printable++;
        }
        if ((double) printable / end < MIN_PRINTABLE) return "";
        return new String(decoded, 0, end, java.nio.charset.StandardCharsets.US_ASCII);
    }

    static boolean isSplitMixConst(long v) {
        return v == GOLDEN || v == MULT1 || v == MULT2;
    }

    static double printableRatio(byte[] bytes, int n) {
        if (n <= 0) return 0;
        int p = 0;
        for (int i = 0; i < n; i++) {
            if (Strings.isPrintable(bytes[i] & 0xFF) || bytes[i] == 0) p++;
        }
        return (double) p / n;
    }

    private static void recoverSplitMix(Program program, Function func, List<Instruction> insns,
                                        List<Long> immediates, List<Address> dataAddrs, int minLen,
                                        List<Hit> hits) {
        var seeds = new LinkedHashSet<Long>();
        for (var v : immediates) {
            if (!isSplitMixConst(v) && v != 0 && Long.bitCount(v) > 8) seeds.add(v);
        }
        var loopLens = findLoopLengths(insns);
        var stackBlob = reconstructStackBlob(program, insns);

        for (var seed : seeds) {
            for (var src : dataAddrs) {
                byte[] raw = read(program, src, MAX_BLOB);
                if (raw.length < minLen) continue;
                tryLengths(func, "splitmix64", loopAddr(insns, seed), Responses.addr(src),
                        seed, raw, loopLens, minLen, hits);
            }
            if (stackBlob.length >= minLen) {
                tryLengths(func, "splitmix64", loopAddr(insns, seed), "stack", seed, stackBlob,
                        loopLens, minLen, hits);
            }
        }
    }

    private static void tryLengths(Function func, String algo, String loop, String blobAddr, long seed,
                                   byte[] raw, Set<Integer> loopLens, int minLen, List<Hit> hits) {
        var decoded = decodeSplitMix(raw, seed);
        var seen = new LinkedHashSet<String>();
        var tryLens = new LinkedHashSet<Integer>();
        tryLens.addAll(loopLens);
        for (int n = minLen; n <= Math.min(raw.length, MAX_BLOB); n++) tryLens.add(n);
        String best = "";
        int bestLen = 0;
        for (int n : tryLens) {
            if (n < minLen || n > decoded.length) continue;
            var slice = new byte[n];
            System.arraycopy(decoded, 0, slice, 0, n);
            var s = longestPrintable(slice, minLen);
            if (s.length() > bestLen) {
                best = s;
                bestLen = s.length();
            }
        }
        if (bestLen >= minLen && seen.add(best) && !looksLikeJunk(best)) {
            hits.add(new Hit(algo, func.getName(), loop, blobAddr, bestLen,
                    "0x" + Long.toHexString(seed), best));
        }
    }

    private static void recoverRollingXor(Program program, Function func, List<Instruction> insns,
                                          int minLen, List<Hit> hits) {
        for (int i = 0; i < insns.size(); i++) {
            var ins = insns.get(i);
            if (!isXor(ins)) continue;
            Long key = xorImm8(ins);
            if (key == null) continue;
            var src = dataAddress(ins, program);
            if (src == null) {
                for (int j = Math.max(0, i - 8); j < i; j++) {
                    src = dataAddress(insns.get(j), program);
                    if (src != null) break;
                }
            }
            if (src == null) continue;
            byte[] raw = read(program, src, 128);
            if (raw.length < minLen) continue;
            for (int inc : new int[]{0, 1, 0x11, 0x13}) {
                var dec = decodeRollingXor(raw, key.intValue(), inc);
                var s = longestPrintable(dec, minLen);
                if (s.length() >= minLen && !looksLikeJunk(s)) {
                    hits.add(new Hit(inc == 0 ? "xor8" : "rolling_xor", func.getName(),
                            Responses.addr(ins.getAddress()), Responses.addr(src), s.length(),
                            "0x" + Integer.toHexString(key.intValue())
                                    + (inc == 0 ? "" : "+0x" + Integer.toHexString(inc)), s));
                    break;
                }
            }
        }
    }

    private static void recoverImmStores(Function func, List<Instruction> insns, int minLen, List<Hit> hits) {
        // dest-reg -> disp -> byte
        var byReg = new LinkedHashMap<String, TreeMap<Long, Integer>>();
        for (var ins : insns) {
            if (!isMov(ins) || ins.getNumOperands() < 2) continue;
            var dst = ins.getDefaultOperandRepresentation(0).toUpperCase(Locale.ROOT);
            if (!dst.contains("BYTE")) continue;
            var srcObjs = ins.getOpObjects(1);
            if (srcObjs.length != 1 || !(srcObjs[0] instanceof Scalar sc)) continue;
            int b = (int) (sc.getUnsignedValue() & 0xFF);
            long disp = 0;
            boolean hasDisp = false;
            for (var o : ins.getOpObjects(0)) {
                if (o instanceof Scalar s) { disp = s.getSignedValue(); hasDisp = true; }
            }
            if (!hasDisp && !dst.contains("[")) continue;
            String reg = dst.replaceAll(".*\\[([^\\]]+).*", "$1");
            if (reg.length() > 24) reg = dst;
            byReg.computeIfAbsent(reg, k -> new TreeMap<>()).put(disp, b);
        }
        for (var e : byReg.entrySet()) {
            var map = e.getValue();
            if (map.size() < minLen) continue;
            var run = new StringBuilder();
            Long prev = null;
            for (var kv : map.entrySet()) {
                if (prev != null && kv.getKey() != prev + 1) {
                    emitImm(func, run, minLen, hits);
                    run.setLength(0);
                }
                int b = kv.getValue();
                if (b == 0) {
                    emitImm(func, run, minLen, hits);
                    run.setLength(0);
                    prev = kv.getKey();
                    continue;
                }
                if (Strings.isPrintable(b)) run.append((char) b);
                else {
                    emitImm(func, run, minLen, hits);
                    run.setLength(0);
                }
                prev = kv.getKey();
            }
            emitImm(func, run, minLen, hits);
        }
    }

    private static void emitImm(Function func, StringBuilder run, int minLen, List<Hit> hits) {
        if (run.length() < minLen) return;
        var s = run.toString();
        if (looksLikeJunk(s)) return;
        hits.add(new Hit("imm_store", func.getName(), Responses.addr(func.getEntryPoint()),
                "", s.length(), "", s));
    }

    private static Set<Integer> findLoopLengths(List<Instruction> insns) {
        var lens = new LinkedHashSet<Integer>();
        for (int i = 0; i < insns.size(); i++) {
            var ins = insns.get(i);
            var mn = ins.getMnemonicString().toUpperCase(Locale.ROOT);
            if (!(mn.startsWith("J") || mn.equals("LOOP"))) continue;
            var flows = ins.getFlows();
            if (flows == null || flows.length == 0) continue;
            if (flows[0].compareTo(ins.getAddress()) >= 0) continue;
            for (int j = Math.max(0, i - 12); j <= i; j++) {
                collectCmpImm(insns.get(j), lens);
            }
        }
        return lens;
    }

    private static void collectCmpImm(Instruction ins, Set<Integer> lens) {
        var mn = ins.getMnemonicString().toUpperCase(Locale.ROOT);
        if (!mn.equals("CMP") && !mn.equals("SUB")) return;
        for (int i = 0; i < ins.getNumOperands(); i++) {
            for (var o : ins.getOpObjects(i)) {
                if (o instanceof Scalar s) {
                    long v = s.getUnsignedValue();
                    if (v >= 4 && v <= MAX_BLOB) lens.add((int) v);
                }
            }
        }
    }

    private static byte[] reconstructStackBlob(Program program, List<Instruction> insns) {
        var byDisp = new TreeMap<Long, byte[]>();
        for (var ins : insns) {
            var mn = ins.getMnemonicString().toUpperCase(Locale.ROOT);
            Long disp = stackDisp(ins);
            if (disp == null) continue;
            if (mn.contains("MOVAPS") || mn.contains("MOVDQA") || mn.contains("MOVUPS")
                    || mn.contains("MOVDQU")) {
                var src = dataAddress(ins, program);
                if (src == null) {
                    var prev = ins.getPrevious();
                    if (prev != null) src = dataAddress(prev, program);
                }
                if (src != null) {
                    var chunk = read(program, src, 16);
                    if (chunk.length > 0) byDisp.put(disp, chunk);
                }
                continue;
            }
            if (!isMov(ins) || ins.getNumOperands() < 2) continue;
            var srcObjs = ins.getOpObjects(1);
            if (srcObjs.length != 1 || !(srcObjs[0] instanceof Scalar sc)) continue;
            int width = storeWidth(ins);
            if (width <= 0) continue;
            var buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(sc.getUnsignedValue());
            var slice = new byte[width];
            System.arraycopy(buf.array(), 0, slice, 0, width);
            byDisp.put(disp, slice);
        }
        if (byDisp.isEmpty()) return new byte[0];
        long min = byDisp.firstKey();
        long max = min;
        for (var e : byDisp.entrySet()) {
            max = Math.max(max, e.getKey() + e.getValue().length);
        }
        int n = (int) Math.min(MAX_BLOB, max - min);
        if (n < 4) return new byte[0];
        var out = new byte[n];
        for (var e : byDisp.entrySet()) {
            int off = (int) (e.getKey() - min);
            var chunk = e.getValue();
            for (int i = 0; i < chunk.length && off + i < out.length; i++) out[off + i] = chunk[i];
        }
        return out;
    }

    private static int storeWidth(Instruction ins) {
        var dst = ins.getDefaultOperandRepresentation(0).toLowerCase(Locale.ROOT);
        if (dst.contains("xmmword") || dst.contains("xmm")) return 16;
        if (dst.contains("qword")) return 8;
        if (dst.contains("dword")) return 4;
        if (dst.contains("word") && !dst.contains("dword") && !dst.contains("qword")) return 2;
        if (dst.contains("byte")) return 1;
        return 4;
    }

    private static Long stackDisp(Instruction ins) {
        if (ins.getNumOperands() < 1) return null;
        var dst = ins.getDefaultOperandRepresentation(0).toUpperCase(Locale.ROOT);
        if (!(dst.contains("RSP") || dst.contains("RBP") || dst.contains("ESP") || dst.contains("EBP"))) {
            return null;
        }
        for (var o : ins.getOpObjects(0)) {
            if (o instanceof Scalar s) return s.getSignedValue();
        }
        return 0L;
    }

    private static Address dataAddress(Instruction ins, Program program) {
        var mem = program.getMemory();
        for (int i = 0; i < ins.getNumOperands(); i++) {
            for (var o : ins.getOpObjects(i)) {
                Address a = null;
                if (o instanceof Address addr) a = addr;
                else if (o instanceof Scalar s) {
                    long v = s.getUnsignedValue();
                    a = program.getAddressFactory().getDefaultAddressSpace().getAddress(v);
                }
                if (a == null || !mem.contains(a)) continue;
                var block = mem.getBlock(a);
                if (block != null && !block.isExecute() && block.isInitialized()) return a;
            }
        }
        return null;
    }

    private static void collectScalars(Instruction ins, List<Long> out) {
        for (int i = 0; i < ins.getNumOperands(); i++) {
            var objs = ins.getOpObjects(i);
            if (objs == null) continue;
            for (var o : objs) {
                if (o instanceof Scalar s) out.add(s.getUnsignedValue());
            }
        }
    }

    private static boolean isXor(Instruction ins) {
        return ins.getMnemonicString().toUpperCase(Locale.ROOT).startsWith("XOR");
    }

    private static boolean isMov(Instruction ins) {
        var mn = ins.getMnemonicString().toUpperCase(Locale.ROOT);
        return mn.equals("MOV") || mn.equals("MOVZX") || mn.equals("MOVSX");
    }

    private static Long xorImm8(Instruction ins) {
        if (ins.getNumOperands() < 2) return null;
        for (var o : ins.getOpObjects(1)) {
            if (o instanceof Scalar s) {
                long v = s.getUnsignedValue();
                if (v > 0 && v < 256) return v;
            }
        }
        return null;
    }

    private static String loopAddr(List<Instruction> insns, long seed) {
        for (var ins : insns) {
            for (int i = 0; i < ins.getNumOperands(); i++) {
                for (var o : ins.getOpObjects(i)) {
                    if (o instanceof Scalar s && s.getUnsignedValue() == seed) {
                        return Responses.addr(ins.getAddress());
                    }
                }
            }
        }
        return insns.isEmpty() ? "" : Responses.addr(insns.get(0).getAddress());
    }

    private static byte[] read(Program program, Address a, int n) {
        var mem = program.getMemory();
        var block = mem.getBlock(a);
        if (block == null || !block.isInitialized()) return new byte[0];
        long avail = block.getEnd().subtract(a) + 1;
        int take = (int) Math.min(n, Math.max(0, avail));
        if (take <= 0) return new byte[0];
        var buf = new byte[take];
        try {
            int got = mem.getBytes(a, buf);
            if (got < take) {
                var slim = new byte[Math.max(0, got)];
                System.arraycopy(buf, 0, slim, 0, slim.length);
                return slim;
            }
            return buf;
        } catch (MemoryAccessException e) {
            return new byte[0];
        }
    }

    private static boolean looksLikeJunk(String s) {
        if (s.length() < 3) return true;
        int alpha = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '/' || c == '.' || c == ':' || c == '-'
                    || c == '_' || c == ' ' || c == '{' || c == '}' || c == '\\') alpha++;
        }
        return (double) alpha / s.length() < 0.6;
    }

}
