package io.github.imjustprism.ghidra.mcp.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public final class Addresses {

    private Addresses() {}

    public static Address parse(Program program, String s) {
        if (s == null || s.isEmpty()) return null;
        try {
            return program.getAddressFactory().getAddress(s);
        } catch (Exception e) {
            return null;
        }
    }

    public static Function functionAtOrContaining(Program program, Address addr) {
        var fm = program.getFunctionManager();
        var f = fm.getFunctionAt(addr);
        return f != null ? f : fm.getFunctionContaining(addr);
    }
}
