package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.DecompileCache;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class TlsSingletons {

    public static final String ASSERT = "0 != Singleton";
    public static final int DEFAULT_MAX = 30;
    public static final int MAX_FUNCTIONS = 120;

    private static final String[] COLS = {
            "slot", "class", "agrees", "known_type", "confidence", "func", "func_addr",
            "site", "source", "line", "funcsig"
    };

    private TlsSingletons() {}

    public static String derive(PluginContext ctx, String klass, int max, boolean apply, Page page,
            Map<String, String> q) {
        int cap = max <= 0 ? DEFAULT_MAX : Math.min(max, MAX_FUNCTIONS);
        return ctx.withProgram(program -> {
            var strAddrs = stringAddresses(program);
            if (strAddrs.isEmpty()) {
                return "# derive_tls_singletons found no defined string \"" + ASSERT + "\"\n"
                        + "# tip: run search kind=text \"0 != Singleton\" and define it, "
                        + "then re-run; tls_singleton_map still has the static table\n";
            }
            var sites = referenceSites(program, strAddrs);
            int skip = Math.max(0, page.offset());
            var rows = new LinkedHashMap<String, Object[]>();
            int scanned = 0;
            int index = 0;
            for (var fn : sites) {
                if (index++ < skip) continue;
                if (scanned >= cap) break;
                scanned++;
                String c;
                try {
                    c = DecompileCache.decompile(program, fn);
                } catch (RuntimeException e) {
                    continue;
                }
                collect(program, fn, c, klass, rows);
            }
            var sb = new StringBuilder(1024);
            sb.append("# derive_tls_singletons sites=").append(sites.size())
              .append(" scanned=").append(scanned).append(" from=").append(skip)
              .append(" slots=").append(rows.size()).append('\n');
            sb.append("# proof shape: ctor or Instance() loads tls_base = "
                    + "ThreadLocalStoragePointer[_tls_index], compares tls_base[slot] against 0 "
                    + "and asserts \"" + ASSERT + "\"; the FUNCSIG names the class\n");
            if (scanned + skip < sites.size()) {
                sb.append("# coverage: ").append(sites.size() - skip - scanned)
                  .append(" reference site(s) not scanned; re-run with offset=")
                  .append(skip + scanned).append(" to continue\n");
            }
            if (rows.isEmpty()) {
                sb.append("# no tls slot derived in the scanned window\n");
                return sb.toString();
            }
            if (apply) {
                var persist = new java.util.LinkedHashMap<Long, String>();
                for (var r : rows.values()) {
                    if (!"exact".equals(r[4])) continue;
                    try {
                        var hex = r[0].toString();
                        var n = hex.startsWith("0x") || hex.startsWith("0X")
                                ? hex.substring(2) : hex;
                        persist.put(Long.parseLong(n, 16), r[1] + "*");
                    } catch (NumberFormatException ignored) {
                    }
                }
                sb.append(TlsSingletonMap.storeDerived(ctx, program, persist));
            }
            var t = Responses.table(q, COLS, rows.size());
            for (var r : rows.values()) t.row(r);
            return sb.append(t.total(rows.size()).build()).toString();
        });
    }

    private static void collect(Program program, Function fn, String c, String klass,
            Map<String, Object[]> rows) {
        var frame = AssertProofs.frame(c);
        var funcAddr = Responses.addr(fn.getEntryPoint());
        for (var site : AssertProofs.sites(c)) {
            if (!ASSERT.equals(site.expr())) continue;
            var owner = AssertProofs.ownerOf(site.sig());
            if (klass != null && !klass.isBlank()
                    && !owner.toLowerCase(Locale.ROOT).contains(klass.trim().toLowerCase(Locale.ROOT))) {
                continue;
            }
            var guard = AssertProofs.guardFor(c, site.start());
            if (guard == null) continue;
            var tls = new ArrayList<AssertProofs.Deref>();
            for (var d : AssertProofs.derefs(guard, frame, site.start())) {
                if (d.resolved() && "tls".equals(d.base())) tls.add(d);
            }
            if (tls.isEmpty()) continue;
            var confidence = tls.size() == 1 ? "exact" : "ambiguous";
            for (var d : tls) {
                var slot = AssertProofs.hex(d.offset());
                var known = TlsSingletonMap.typeAt(d.offset());
                var agrees = known == null ? "new"
                        : known.toLowerCase(Locale.ROOT).contains(shortName(owner).toLowerCase(Locale.ROOT))
                                ? "yes" : "conflict";
                rows.putIfAbsent(slot + "|" + owner, new Object[]{
                        slot, owner, agrees, known == null ? "" : known, confidence,
                        fn.getName(), funcAddr, siteAddress(program, fn, site.expr()),
                        site.file(), AssertProofs.hex(site.line()), site.sig()
                });
            }
        }
    }

    private static String shortName(String owner) {
        int i = owner.lastIndexOf("::");
        return i < 0 ? owner : owner.substring(i + 2);
    }

    private static List<Address> stringAddresses(Program program) {
        var out = new ArrayList<Address>();
        var it = program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            var data = it.next();
            if (data == null || !DataTypes.isStringLike(data)) continue;
            var v = data.getValue();
            if (v == null || !ASSERT.equals(v.toString())) continue;
            out.add(data.getAddress());
        }
        return out;
    }

    private static List<Function> referenceSites(Program program, List<Address> strings) {
        var seen = new LinkedHashSet<Address>();
        var out = new ArrayList<Function>();
        var fm = program.getFunctionManager();
        for (var s : strings) {
            for (var ref : program.getReferenceManager().getReferencesTo(s)) {
                var fn = fm.getFunctionContaining(ref.getFromAddress());
                if (fn == null || !seen.add(fn.getEntryPoint())) continue;
                out.add(fn);
            }
        }
        return out;
    }

    private static String siteAddress(Program program, Function fn, String expr) {
        var listing = program.getListing();
        var it = listing.getInstructions(fn.getBody(), true);
        while (it.hasNext()) {
            var ins = it.next();
            for (var ref : ins.getReferencesFrom()) {
                var d = listing.getDataAt(ref.getToAddress());
                if (d == null || !DataTypes.isStringLike(d)) continue;
                var v = d.getValue();
                if (v != null && expr.equals(v.toString())) return Responses.addr(ins.getAddress());
            }
        }
        return "";
    }
}
