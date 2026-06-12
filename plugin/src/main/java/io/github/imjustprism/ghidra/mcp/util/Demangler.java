package io.github.imjustprism.ghidra.mcp.util;

import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

public final class Demangler {

    private Demangler() {}

    public static String demangleSymbol(String mangled) {
        if (mangled == null || mangled.isEmpty()) throw new IllegalArgumentException("Mangled name is required");
        try {
            var obj = ghidra.app.util.demangler.DemanglerUtil.demangle(mangled);
            if (obj != null) {
                var sig = obj.getSignature(false);
                return sig != null && !sig.isEmpty() ? sig : obj.getName();
            }
        } catch (Exception e) {
            Msg.trace(Demangler.class, "demangle failed for " + mangled, e);
        }
        return mangled;
    }

    public static String demangleAll(PluginContext ctx) {
        var program = ctx.currentProgram();
        if (program == null) return "No program loaded";
        var counter = new int[1];
        var failed = new int[1];
        ctx.runOnSwingTx(program, "Demangle all symbols", () -> {
            var st = program.getSymbolTable();
            for (var sym : st.getAllSymbols(true)) {
                var name = sym.getName();
                if (name == null || name.isEmpty()) continue;
                if (!(name.startsWith("_Z") || name.startsWith("?") || name.startsWith("__Z"))) continue;
                try {
                    var obj = ghidra.app.util.demangler.DemanglerUtil.demangle(name);
                    if (obj == null) { failed[0]++; continue; }
                    var demangled = obj.getName();
                    if (demangled == null || demangled.isEmpty() || demangled.equals(name)) {
                        failed[0]++;
                        continue;
                    }
                    sym.setName(demangled, SourceType.ANALYSIS);
                    counter[0]++;
                } catch (Exception e) {
                    failed[0]++;
                }
            }
            return true;
        });
        return "Demangled: " + counter[0] + " (failed: " + failed[0] + ")";
    }
}
