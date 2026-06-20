package io.github.imjustprism.ghidra.mcp.util;

import java.util.Set;

public final class Registers {

    private static final Set<String> COMMON = Set.of(
            "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP", "EIP",
            "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "RIP",
            "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
            "CS", "DS", "ES", "FS", "GS", "SS",
            "EFLAGS", "RFLAGS");

    private Registers() {
    }

    public static boolean isCommon(String name) {
        return name != null && (COMMON.contains(name) || COMMON.contains(name.toUpperCase()));
    }
}
