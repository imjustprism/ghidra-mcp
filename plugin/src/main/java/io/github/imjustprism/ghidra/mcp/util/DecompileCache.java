package io.github.imjustprism.ghidra.mcp.util;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.Map;

public final class DecompileCache {

    public static final int CAPACITY = 64;

    public static final int TIMEOUT_SEC = 30;

    private record Key(Address entry, long modNumber) {}

    private static final Map<Key, String> CACHE = Caches.lru(CAPACITY);

    private DecompileCache() {}

    public static String decompile(Program program, Function func) {
        var key = new Key(func.getEntryPoint(), program.getModificationNumber());
        var hit = CACHE.get(key);
        if (hit != null) return hit;
        var decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            var result = decomp.decompileFunction(func, TIMEOUT_SEC, new ConsoleTaskMonitor());
            var c = result != null && result.decompileCompleted()
                    ? result.getDecompiledFunction().getC()
                    : "Decompilation failed";
            CACHE.put(key, c);
            return c;
        } finally {
            decomp.dispose();
        }
    }

    public static void clear() { CACHE.clear(); }
}
