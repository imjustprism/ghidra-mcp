package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.ArrayList;
import java.util.Map;

public final class StackStrings {

    private StackStrings() {}

    public static String find(PluginContext ctx, String addr, Page p, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) return "No function at " + addr;
            var listing = program.getListing();
            var body = func.getBody();
            var byOffset = new java.util.TreeMap<Long, Integer>();
            var instrs = listing.getInstructions(body, true);
            while (instrs.hasNext()) {
                var ins = instrs.next();
                if (!"MOV".equalsIgnoreCase(ins.getMnemonicString())) continue;
                if (ins.getNumOperands() != 2) continue;
                var dst = ins.getDefaultOperandRepresentation(0);
                if (!dst.contains("byte")) continue;
                if (!(dst.contains("RSP") || dst.contains("RBP") || dst.contains("ESP") || dst.contains("EBP"))) continue;
                var srcObjs = ins.getOpObjects(1);
                if (srcObjs.length != 1) continue;
                if (!(srcObjs[0] instanceof ghidra.program.model.scalar.Scalar sc)) continue;
                long imm = sc.getUnsignedValue() & 0xFF;
                long disp = 0;
                for (var o : ins.getOpObjects(0)) {
                    if (o instanceof ghidra.program.model.scalar.Scalar s) { disp = s.getSignedValue(); break; }
                }
                byOffset.put(disp, (int) imm);
            }
            if (byOffset.isEmpty()) return "# no stack-string patterns\n";
            var groups = new ArrayList<java.util.List<Integer>>();
            java.util.List<Integer> cur = null;
            long prev = Long.MIN_VALUE;
            for (var e : byOffset.entrySet()) {
                if (cur == null || e.getKey() != prev + 1) {
                    cur = new ArrayList<>();
                    groups.add(cur);
                }
                cur.add(e.getValue());
                prev = e.getKey();
            }
            var t = Responses.table(p, q, new String[]{"len", "xor", "value"});
            var w = new Responses.Window(p);
            for (var g : groups) {
                if (g.size() < 4) continue;
                if (!w.take()) continue;
                var raw = new byte[g.size()];
                for (int i = 0; i < raw.length; i++) raw[i] = g.get(i).byteValue();
                int bestKey = 0, bestScore = -1;
                for (int k = 0; k < 256; k++) {
                    int score = 0;
                    for (var b : raw) {
                        int v = (b ^ k) & 0xFF;
                        if ((v >= 0x20 && v < 0x7F) || v == 0) score++;
                    }
                    if (score > bestScore) { bestScore = score; bestKey = k; }
                }
                var sb = new StringBuilder(raw.length);
                for (var b : raw) sb.append((char) ((b ^ bestKey) & 0xFF));
                t.row(raw.length, "%02x".formatted(bestKey), Strings.escapeString(sb.toString()));
            }
            return t.total(w.total()).build();
        });
    }
}
