package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * License / crackme compare sites: strcmp/memcmp against literals, CMP with
 * large immediates, and xrefs to subscription/serial/HWID strings.
 */
public final class SecretCompares {

    private static final String[] CMP_APIS = {
            "strcmp", "strncmp", "memcmp", "bcmp", "lstrcmpA", "lstrcmpW", "lstrcmpiA",
            "wcscmp", "wcsncmp", "RtlCompareMemory", "CryptBinaryToStringA"
    };

    private static final String[] LICENSE_WORDS = {
            "serial", "license", "licence", "hwid", "subscription", "expired", "activation",
            "product key", "trial", "watermark", "drm", "sessionsecret", "accesstoken",
            "valid key", "invalid key", "no active", "frozen", "latestversion"
    };

    private SecretCompares() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var rows = new ArrayList<String[]>();
            scanCmpApis(program, rows);
            scanLicenseStrings(program, rows);
            scanFatImmediates(program, rows);
            var t = Responses.table(p, q, new String[]{"kind", "func", "addr", "value"});
            var w = new Responses.Window(p);
            int total = 0;
            var seen = new java.util.HashSet<String>();
            for (var r : rows) {
                var key = r[0] + "|" + r[2] + "|" + r[3];
                if (!seen.add(key)) continue;
                total++;
                if (!w.take()) continue;
                t.row(r[0], r[1], r[2], Strings.escapeString(r[3]));
            }
            return "# find_secret_compares\n" + t.total(total).build();
        });
    }

    static boolean isLicenseWord(String s) {
        if (s == null) return false;
        var low = s.toLowerCase(Locale.ROOT);
        for (var w : LICENSE_WORDS) if (low.contains(w)) return true;
        return false;
    }

    static boolean isCmpApi(String name) {
        if (name == null) return false;
        var n = name.startsWith("__imp_") ? name.substring(6) : name;
        if (n.startsWith("_") && n.length() > 1) n = n.substring(1);
        for (var a : CMP_APIS) if (a.equals(n)) return true;
        return false;
    }

    private static void scanCmpApis(Program program, List<String[]> rows) {
        var st = program.getSymbolTable();
        var fm = program.getFunctionManager();
        for (var api : CMP_APIS) {
            for (var prefix : new String[]{"", "_", "__imp_"}) {
                for (var sym : st.getSymbols(prefix + api)) {
                    for (var ref : program.getReferenceManager().getReferencesTo(sym.getAddress())) {
                        if (!ref.getReferenceType().isCall()) continue;
                        var fn = fm.getFunctionContaining(ref.getFromAddress());
                        var lit = nearbyString(program, fn, ref.getFromAddress());
                        rows.add(new String[]{"cmp_api", fn == null ? "" : fn.getName(),
                                Responses.addr(ref.getFromAddress()),
                                api + (lit.isEmpty() ? "" : " vs \"" + lit + "\"")});
                    }
                }
            }
        }
    }

    private static void scanLicenseStrings(Program program, List<String[]> rows) {
        var listing = program.getListing();
        var fm = program.getFunctionManager();
        var it = listing.getDefinedData(true);
        while (it.hasNext()) {
            var d = it.next();
            if (d == null || !DataTypes.isStringLike(d) || d.getValue() == null) continue;
            var s = d.getValue().toString();
            if (!isLicenseWord(s)) continue;
            for (var ref : program.getReferenceManager().getReferencesTo(d.getAddress())) {
                var fn = fm.getFunctionContaining(ref.getFromAddress());
                rows.add(new String[]{"license_str", fn == null ? "" : fn.getName(),
                        Responses.addr(ref.getFromAddress()), s});
            }
        }
    }

    private static void scanFatImmediates(Program program, List<String[]> rows) {
        var listing = program.getListing();
        int n = 0;
        for (var f : program.getFunctionManager().getFunctions(true)) {
            if (f.isThunk() || f.isExternal()) continue;
            if (n++ > 4000) break;
            var ins = listing.getInstructions(f.getBody(), true);
            while (ins.hasNext()) {
                Instruction i = ins.next();
                var mn = i.getMnemonicString().toUpperCase(Locale.ROOT);
                if (!mn.equals("CMP") && !mn.equals("SUB")) continue;
                for (int op = 0; op < i.getNumOperands(); op++) {
                    for (var o : i.getOpObjects(op)) {
                        if (!(o instanceof Scalar sc)) continue;
                        long v = sc.getUnsignedValue();
                        if (v > 0x10000L && Long.bitCount(v) > 8 && !HiddenStrings.isSplitMixConst(v)) {
                            rows.add(new String[]{"imm_cmp", f.getName(), Responses.addr(i.getAddress()),
                                    "0x" + Long.toHexString(v)});
                        }
                    }
                }
            }
        }
    }

    private static String nearbyString(Program program, Function fn, ghidra.program.model.address.Address site) {
        if (fn == null) return "";
        var listing = program.getListing();
        var ins = listing.getInstructionAt(site);
        for (int i = 0; i < 12 && ins != null; i++) {
            ins = ins.getPrevious();
            if (ins == null || !fn.getBody().contains(ins.getAddress())) break;
            for (var ref : ins.getReferencesFrom()) {
                var data = listing.getDataAt(ref.getToAddress());
                if (data != null && DataTypes.isStringLike(data) && data.getValue() != null) {
                    var s = data.getValue().toString();
                    if (s.length() >= 2) return s.length() > 48 ? s.substring(0, 48) : s;
                }
            }
        }
        return "";
    }
}
