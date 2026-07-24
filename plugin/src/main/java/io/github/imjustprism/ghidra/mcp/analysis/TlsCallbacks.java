package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.mem.MemoryAccessException;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class TlsCallbacks {

    private static final int MAX_CALLBACKS = 64;

    private TlsCallbacks() {}

    public static String list(PluginContext ctx, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var mem = program.getMemory();
            var base = program.getImageBase();
            var space = program.getAddressFactory().getDefaultAddressSpace();
            try {
                int lfanew = mem.getInt(base.add(0x3c));
                var pe = base.add(lfanew & 0xffffffffL);
                if (mem.getInt(pe) != 0x00004550) return "not a PE — TLS-callback enumeration is PE-only";
                var opt = pe.add(24);
                boolean plus = (mem.getShort(opt) & 0xffff) == 0x20b;
                int dirOff = plus ? 0xB8 : 0xA8;
                long tlsRva = mem.getInt(opt.add(dirOff)) & 0xffffffffL;
                if (tlsRva == 0) return "# no TLS directory (no TLS callbacks)\n";
                var tls = base.add(tlsRva);
                long cbVa = plus ? mem.getLong(tls.add(0x18)) : (mem.getInt(tls.add(0x0c)) & 0xffffffffL);
                if (cbVa == 0) return "# TLS directory present, AddressOfCallBacks=0 (no callbacks)\n";
                var arr = space.getAddress(cbVa);
                var t = Responses.table(q, new String[]{"i", "callback", "function"}, 8);
                int n = 0;
                for (int i = 0; i < MAX_CALLBACKS; i++) {
                    long cb = plus ? mem.getLong(arr.add((long) i * 8))
                            : (mem.getInt(arr.add((long) i * 4)) & 0xffffffffL);
                    if (cb == 0) break;
                    var fa = space.getAddress(cb);
                    var fn = program.getFunctionManager().getFunctionContaining(fa);
                    t.row(i, Responses.addr(fa), fn == null ? "" : fn.getName());
                    n++;
                }
                return "# TLS callbacks (run before the entry point — a common anti-debug / init-hiding spot): "
                        + n + "\n" + t.total(n).build();
            } catch (MemoryAccessException e) {
                return "failed to read TLS directory: " + e.getMessage();
            }
        });
    }
}
