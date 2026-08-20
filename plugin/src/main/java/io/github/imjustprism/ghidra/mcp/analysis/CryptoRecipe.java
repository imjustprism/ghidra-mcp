package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Reconstruct per-function crypto recipes from BCrypt/WinCrypt call order +
 * nearby algorithm strings (SHA256, GCM, HMAC, |drm-v1).
 */
public final class CryptoRecipe {

    private static final String[] CRYPTO_APIS = {
            "BCryptOpenAlgorithmProvider", "BCryptCreateHash", "BCryptHashData", "BCryptFinishHash",
            "BCryptGenerateSymmetricKey", "BCryptEncrypt", "BCryptDecrypt", "BCryptGenRandom",
            "BCryptSetProperty", "BCryptGetProperty", "BCryptDestroyKey", "BCryptDestroyHash",
            "CryptAcquireContextA", "CryptAcquireContextW", "CryptCreateHash", "CryptHashData",
            "CryptDeriveKey", "CryptEncrypt", "CryptDecrypt", "CryptGenRandom", "CryptImportKey"
    };

    private CryptoRecipe() {}

    public static String recover(PluginContext ctx, String addr, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var recipes = new ArrayList<Recipe>();
            if (addr != null && !addr.isBlank()) {
                var a = Addresses.resolve(program, addr);
                if (a == null) throw new IllegalArgumentException("invalid address: " + addr);
                var func = Addresses.functionAtOrContaining(program, a);
                if (func == null) throw new IllegalArgumentException("no function at " + addr);
                var r = fromFunction(program, func);
                if (r != null) recipes.add(r);
            } else {
                int n = 0;
                for (var f : program.getFunctionManager().getFunctions(true)) {
                    if (f.isThunk() || f.isExternal()) continue;
                    if (n++ > 6000) break;
                    var r = fromFunction(program, f);
                    if (r != null) recipes.add(r);
                }
            }
            var t = Responses.table(p, q, new String[]{"func", "addr", "kind", "steps", "hints"});
            var w = new Responses.Window(p);
            for (var r : recipes) {
                if (!w.take()) continue;
                t.row(r.func, r.addr, r.kind, r.steps, Strings.escapeString(r.hints));
            }
            return "# recover_crypto_recipe " + recipes.size() + " function(s)\n"
                    + t.total(w.total()).build();
        });
    }

    static Recipe fromFunction(Program program, Function func) {
        var steps = new ArrayList<String>();
        var listing = program.getListing();
        var st = program.getSymbolTable();
        var fm = program.getFunctionManager();
        for (var insn : listing.getInstructions(func.getBody(), true)) {
            for (var ref : insn.getReferencesFrom()) {
                if (!ref.getReferenceType().isCall()) continue;
                var to = ref.getToAddress();
                String name = null;
                if (to.isExternalAddress()) {
                    var sym = st.getPrimarySymbol(to);
                    name = sym == null ? "" : strip(sym.getName());
                } else {
                    var callee = fm.getFunctionAt(to);
                    if (callee != null && callee.isThunk()) {
                        var th = callee.getThunkedFunction(true);
                        if (th != null) name = strip(th.getName());
                    } else if (callee != null) {
                        name = strip(callee.getName());
                    }
                }
                if (name != null && isCryptoApi(name)) steps.add(name);
            }
        }
        if (steps.size() < 2) return null;
        var hints = stringHints(program, func);
        return new Recipe(func.getName(), Responses.addr(func.getEntryPoint()),
                classify(steps, hints), String.join(" -> ", steps), hints);
    }

    static String classify(List<String> steps, String hints) {
        var blob = String.join(" ", steps).toLowerCase(Locale.ROOT) + " " + hints.toLowerCase(Locale.ROOT);
        if (blob.contains("decrypt") && (blob.contains("gcm") || blob.contains("chainingmode"))) {
            return "aes_gcm_decrypt";
        }
        if (blob.contains("encrypt") && blob.contains("gcm")) return "aes_gcm_encrypt";
        if (blob.contains("encrypt") || blob.contains("decrypt")) return "symmetric";
        if (blob.contains("createhash") || blob.contains("hashdata") || blob.contains("sha")) {
            if (blob.contains("hmac") || blob.contains("finishhash") && blob.contains("generaterandom")) {
                return "hmac";
            }
            return "hash";
        }
        if (blob.contains("genrandom")) return "rng";
        return "crypto";
    }

    static boolean isCryptoApi(String name) {
        for (var a : CRYPTO_APIS) if (a.equals(name)) return true;
        return name.startsWith("BCrypt") || name.startsWith("Crypt");
    }

    private static String strip(String name) {
        if (name.startsWith("__imp_")) return name.substring(6);
        if (name.startsWith("_") && name.length() > 1) return name.substring(1);
        return name;
    }

    private static String stringHints(Program program, Function func) {
        var hints = new LinkedHashSet<String>();
        var listing = program.getListing();
        var refs = program.getReferenceManager();
        var iter = func.getBody().getAddresses(true);
        while (iter.hasNext()) {
            var from = iter.next();
            for (var r : refs.getReferencesFrom(from)) {
                var data = listing.getDataAt(r.getToAddress());
                if (data == null || !DataTypes.isStringLike(data) || data.getValue() == null) continue;
                var s = data.getValue().toString();
                var low = s.toLowerCase(Locale.ROOT);
                if (low.contains("sha") || low.contains("aes") || low.contains("gcm")
                        || low.contains("hmac") || low.contains("chaining") || low.contains("|drm")
                        || low.contains("md5") || low.contains("objectlength")) {
                    hints.add(s.length() > 40 ? s.substring(0, 40) : s);
                }
            }
        }
        return String.join("; ", hints);
    }

    record Recipe(String func, String addr, String kind, String steps, String hints) {}
}
