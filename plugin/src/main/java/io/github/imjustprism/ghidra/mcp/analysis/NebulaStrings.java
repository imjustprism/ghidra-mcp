package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.function.Predicate;

public final class NebulaStrings {

    public record Hit(Address addr, String value) {}

    private NebulaStrings() {}

    public static List<Hit> defined(Program program, Predicate<String> pred) {
        var out = new ArrayList<Hit>();
        var it = program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            var data = it.next();
            if (data == null || !DataTypes.isStringLike(data)) continue;
            var v = data.getValue();
            if (v == null) continue;
            var s = v.toString();
            if (pred != null && !pred.test(s)) continue;
            out.add(new Hit(data.getAddress(), s));
        }
        return out;
    }

    public static List<Function> referrers(Program program, Address to) {
        var out = new ArrayList<Function>();
        var seen = new LinkedHashSet<Address>();
        var fm = program.getFunctionManager();
        for (var ref : program.getReferenceManager().getReferencesTo(to)) {
            var fn = fm.getFunctionContaining(ref.getFromAddress());
            if (fn == null || fn.isExternal() || fn.isThunk()) continue;
            if (seen.add(fn.getEntryPoint())) out.add(fn);
        }
        return out;
    }

    public static int inbound(Program program, Function fn) {
        int n = 0;
        var it = program.getReferenceManager().getReferencesTo(fn.getEntryPoint());
        while (it.hasNext()) {
            it.next();
            n++;
        }
        return n;
    }

    public static int inboundCalls(Program program, Function fn) {
        int n = 0;
        var it = program.getReferenceManager().getReferencesTo(fn.getEntryPoint());
        while (it.hasNext()) {
            var ref = it.next();
            var t = ref.getReferenceType();
            if (t.isCall() || t.isJump()) n++;
        }
        return n;
    }

    public static Function pickHub(Program program, String needle) {
        Function best = null;
        int bestIn = -1;
        for (var hit : defined(program, s -> s.contains(needle))) {
            for (var fn : referrers(program, hit.addr())) {
                int n = inbound(program, fn);
                if (n > bestIn) {
                    best = fn;
                    bestIn = n;
                }
            }
        }
        return best;
    }

    public static List<Function> callersOf(Program program, Function hub) {
        var out = new ArrayList<Function>();
        var seen = new LinkedHashSet<Address>();
        var fm = program.getFunctionManager();
        var it = program.getReferenceManager().getReferencesTo(hub.getEntryPoint());
        while (it.hasNext()) {
            var ref = it.next();
            var t = ref.getReferenceType();
            if (!t.isCall() && !t.isJump() && t != RefType.DATA && !t.isData()) continue;
            if (Unwind.inPdata(program, ref.getFromAddress())) continue;
            var fn = fm.getFunctionContaining(ref.getFromAddress());
            if (fn == null || fn.isExternal() || fn.getEntryPoint().equals(hub.getEntryPoint())) {
                continue;
            }
            if (seen.add(fn.getEntryPoint())) out.add(fn);
        }
        return out;
    }

    public static List<String> stringsIn(Program program, Function fn) {
        var out = new ArrayList<String>();
        var seen = new LinkedHashSet<String>();
        var listing = program.getListing();
        var it = listing.getInstructions(fn.getBody(), true);
        while (it.hasNext()) {
            var ins = it.next();
            for (var ref : ins.getReferencesFrom()) {
                var d = listing.getDataAt(ref.getToAddress());
                if (d == null || !DataTypes.isStringLike(d)) continue;
                var v = d.getValue();
                if (v == null) continue;
                var s = v.toString();
                if (seen.add(s)) out.add(s);
            }
        }
        return out;
    }
}
