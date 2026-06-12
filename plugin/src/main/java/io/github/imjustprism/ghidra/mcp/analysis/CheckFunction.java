package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class CheckFunction {

    private CheckFunction() {}

    private static final String[] SUCCESS_WORDS = {
        "correct", "granted", "winner", "flag{", "you win",
        "success", "welcome", "unlock", "passed", "congrat"
    };

    private static final String[] FAIL_WORDS = {
        "wrong", "denied", "invalid", "incorrect", "try again",
        "failed", "rejected", "nope", "bad", "error"
    };

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var successAddrs = stringsMatching(program, SUCCESS_WORDS);
            var failAddrs = stringsMatching(program, FAIL_WORDS);

            Map<Function, int[]> scores = new HashMap<>();
            tally(program, successAddrs, scores, 0);
            tally(program, failAddrs, scores, 1);

            var t = Responses.table(p, q, new String[]{"addr", "name", "score", "success_refs", "fail_refs"});
            var entries = scores.entrySet().stream()
                .filter(e -> e.getValue()[0] > 0 && e.getValue()[1] > 0)
                .sorted((a, b) -> {
                    int sa = a.getValue()[0] + a.getValue()[1];
                    int sb = b.getValue()[0] + b.getValue()[1];
                    return Integer.compare(sb, sa);
                })
                .toList();
            var w = new Responses.Window(p);
            for (var e : entries) {
                if (!w.take()) continue;
                var f = e.getKey();
                int s = e.getValue()[0];
                int fl = e.getValue()[1];
                t.row(Responses.addr(f.getEntryPoint()), f.getName(), s + fl, s, fl);
            }
            return t.total(w.total()).build();
        });
    }

    private static Set<Address> stringsMatching(Program program, String[] needles) {
        var out = new HashSet<Address>();
        var it = program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            Data d = it.next();
            if (d == null || !DataTypes.isStringLike(d)) continue;
            var v = d.getValue();
            if (v == null) continue;
            var lower = v.toString().toLowerCase(Locale.ROOT);
            for (var n : needles) {
                if (lower.contains(n)) {
                    out.add(d.getAddress());
                    break;
                }
            }
        }
        return out;
    }

    private static void tally(Program program, Set<Address> targets, Map<Function, int[]> scores, int slot) {
        var refMgr = program.getReferenceManager();
        for (var addr : targets) {
            ReferenceIterator it = refMgr.getReferencesTo(addr);
            while (it.hasNext()) {
                Reference r = it.next();
                Function f = program.getFunctionManager().getFunctionContaining(r.getFromAddress());
                if (f == null) continue;
                scores.computeIfAbsent(f, k -> new int[2])[slot]++;
            }
        }
    }
}
