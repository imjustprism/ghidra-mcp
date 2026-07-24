package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

public final class DynamicApi {

    private static final List<String> RESOLVERS = List.of(
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetModuleHandleA", "GetModuleHandleW", "LdrGetProcedureAddress", "LdrLoadDll", "dlsym", "dlopen"
    );

    private static final List<String> PREFIXES = List.of("", "_", "__imp_");

    private static final int BACK_SCAN = 16;

    private DynamicApi() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var st = program.getSymbolTable();
            var refs = program.getReferenceManager();
            var fm = program.getFunctionManager();
            var seen = new HashSet<Address>();
            var rows = new ArrayList<Object[]>();
            long off = p.offset();
            long lim = p.limit();
            long total = 0;
            for (var base : RESOLVERS) {
                for (var prefix : PREFIXES) {
                    for (var sym : st.getSymbols(prefix + base)) {
                        var it = refs.getReferencesTo(sym.getAddress());
                        while (it.hasNext()) {
                            var r = it.next();
                            if (!r.getReferenceType().isCall()) continue;
                            var from = r.getFromAddress();
                            if (!from.isMemoryAddress() || !seen.add(from)) continue;
                            var fn = fm.getFunctionContaining(from);
                            if (total >= off && rows.size() < lim) {
                                rows.add(new Object[]{Responses.addr(from), fn != null ? fn.getName() : "",
                                        base, resolvedName(program, from, base)});
                            }
                            total++;
                        }
                    }
                }
            }
            var t = Responses.table(p, q, new String[]{"site", "caller", "resolver", "api"});
            for (var row : rows) {
                t.row(row);
            }
            return t.total((int) Math.min(total, Integer.MAX_VALUE)).build();
        });
    }

    private static String resolvedName(Program program, Address site, String resolver) {
        var regName = nameRegister(resolver);
        if (regName == null) return "";
        var target = program.getRegister(regName);
        if (target == null) return "";
        var base = target.getBaseRegister();
        var ins = program.getListing().getInstructionAt(site);
        if (ins == null) return "";
        var fn = program.getFunctionManager().getFunctionContaining(site);
        for (int i = 0; i < BACK_SCAN; i++) {
            ins = ins.getPrevious();
            if (ins == null) break;
            if (fn != null && !fn.getBody().contains(ins.getAddress())) break;
            for (var ro : ins.getResultObjects()) {
                if (!(ro instanceof Register r) || !base.equals(r.getBaseRegister())) continue;
                if (!ins.getMnemonicString().equalsIgnoreCase("LEA")) return "";
                for (var ref : ins.getReferencesFrom()) {
                    var s = cStringAt(program, ref.getToAddress());
                    if (s != null) return s;
                }
                return "";
            }
        }
        return "";
    }

    private static String nameRegister(String resolver) {
        return switch (resolver) {
            case "GetProcAddress" -> "RDX";
            case "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
                    "GetModuleHandleA", "GetModuleHandleW" -> "RCX";
            default -> null;
        };
    }

    private static String cStringAt(Program program, Address addr) {
        var data = program.getListing().getDataContaining(addr);
        if (data != null && DataTypes.isStringLike(data) && data.getValue() != null) {
            return data.getValue().toString();
        }
        var buf = new byte[64];
        int n;
        try {
            n = program.getMemory().getBytes(addr, buf);
        } catch (ghidra.program.model.mem.MemoryAccessException e) {
            return null;
        }
        int len = 0;
        while (len < n && buf[len] >= 0x20 && buf[len] < 0x7f) len++;
        return len >= 2 && (len == n || buf[len] == 0)
                ? new String(buf, 0, len, StandardCharsets.US_ASCII) : null;
    }
}
