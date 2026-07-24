package io.github.imjustprism.ghidra.mcp.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

import java.util.LinkedHashSet;
import java.util.Set;

public final class Imports {

    private Imports() {}

    public static Set<Address> callSites(Program program, Symbol external) {
        var rm = program.getReferenceManager();
        var sites = new LinkedHashSet<Address>();
        for (var ref : rm.getReferencesTo(external.getAddress())) {
            var from = ref.getFromAddress();
            if (ref.getReferenceType().isData() && from.isMemoryAddress()) {
                for (var slotRef : rm.getReferencesTo(from)) sites.add(slotRef.getFromAddress());
            } else {
                sites.add(from);
            }
        }
        return sites;
    }

    public static String iatSlot(Program program, Address externalAddr) {
        for (var ref : program.getReferenceManager().getReferencesTo(externalAddr)) {
            var from = ref.getFromAddress();
            if (ref.getReferenceType().isData() && from.isMemoryAddress()) return Responses.addr(from);
        }
        return "";
    }
}
