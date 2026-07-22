package io.github.imjustprism.ghidra.mcp.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public final class Addresses {

    private Addresses() {}

    public static Address parse(Program program, String s) {
        return raw(program, s);
    }

    public static Address resolve(Program program, String s) {
        if (s == null || s.isBlank()) return null;
        var t = s.trim();
        if (t.regionMatches(true, 0, "rva:", 0, 4)) return rebase(program, t.substring(4).trim());
        var a = raw(program, t);
        if (a != null && program.getMemory().contains(a)) return a;
        var rva = rebase(program, t);
        return rva != null && program.getMemory().contains(rva) ? rva : a;
    }

    public static Function resolveFunction(Program program, String s) {
        var f = Programs.findFunctionByName(program, s == null ? "" : s.trim());
        if (f != null) return f;
        var a = resolve(program, s);
        return a == null ? null : functionAtOrContaining(program, a);
    }

    public static Function functionAtOrContaining(Program program, Address addr) {
        var fm = program.getFunctionManager();
        var f = fm.getFunctionAt(addr);
        return f != null ? f : fm.getFunctionContaining(addr);
    }

    private static Address raw(Program program, String s) {
        if (s == null || s.isEmpty()) return null;
        try {
            return program.getAddressFactory().getAddress(s);
        } catch (Exception e) {
            return null;
        }
    }

    private static Address rebase(Program program, String s) {
        var off = raw(program, s);
        if (off == null) return null;
        try {
            var base = program.getImageBase();
            return base.getNewAddress(base.getOffset() + off.getOffset());
        } catch (Exception e) {
            return null;
        }
    }
}
