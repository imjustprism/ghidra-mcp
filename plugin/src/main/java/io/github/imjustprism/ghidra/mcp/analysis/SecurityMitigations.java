package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class SecurityMitigations {

    private SecurityMitigations() {}

    public static String detect(PluginContext ctx, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var mem = program.getMemory();
            var base = program.getImageBase();
            try {
                int lfanew = mem.getInt(base.add(0x3c));
                var pe = base.add(lfanew & 0xffffffffL);
                if (mem.getInt(pe) != 0x00004550) {
                    return "not a PE (no PE\\0\\0 signature at e_lfanew) — this decode is PE-only";
                }
                var opt = pe.add(24);
                int magic = mem.getShort(opt) & 0xffff;
                boolean plus = magic == 0x20b;
                int dll = mem.getShort(opt.add(0x46)) & 0xffff;
                var t = Responses.table(q, new String[]{"mitigation", "enabled"}, 9);
                t.row("ASLR (DYNAMICBASE)", yn(dll, 0x0040));
                t.row("High-Entropy ASLR", plus ? yn(dll, 0x0020) : "n/a (32-bit)");
                t.row("DEP/NX (NX_COMPAT)", yn(dll, 0x0100));
                t.row("Control Flow Guard (GUARD_CF)", yn(dll, 0x4000));
                t.row("SEH disabled (NO_SEH)", yn(dll, 0x0400));
                t.row("Force Integrity", yn(dll, 0x0080));
                t.row("AppContainer", yn(dll, 0x1000));
                t.row("Terminal-Server Aware", yn(dll, 0x8000));
                t.row("/GS stack cookie (heuristic)",
                        hasSymbol(program, "__security_check_cookie") || hasSymbol(program, "__security_cookie")
                                ? "yes" : "no");
                return "# security mitigations (PE32" + (plus ? "+" : "")
                        + ", DllCharacteristics=0x" + Integer.toHexString(dll) + ")\n" + t.build();
            } catch (MemoryAccessException e) {
                return "failed to read PE header from image base: " + e.getMessage();
            }
        });
    }

    private static String yn(int value, int mask) {
        return (value & mask) != 0 ? "yes" : "no";
    }

    private static boolean hasSymbol(Program program, String name) {
        return program.getSymbolTable().getSymbols(name).hasNext();
    }
}
