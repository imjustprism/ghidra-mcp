package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.DecompileCache;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public final class ProveOffset {

    public static final int DEFAULT_MAX = 25;
    public static final int MAX_FUNCTIONS = 200;
    private static final int SHAPE_BUDGET = 4;

    private static final String[] COLS = {
            "class", "field", "offset", "width", "base", "container", "confidence",
            "assert", "source", "line", "site", "func", "func_addr", "funcsig", "detail"
    };

    private static final Pattern STAR_VAR = Pattern.compile("\\*\\s*([A-Za-z_][A-Za-z0-9_]*)");
    private static final Pattern BASE_VAR = Pattern.compile("\\(\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*\\+");

    private ProveOffset() {}

    public record Proof(String owner, String field, String offset, String width, String base,
            String container, String confidence, String assertExpr, String source, String line,
            String site, String func, String funcAddr, String funcsig, String detail) {
        Object[] cells() {
            return new Object[]{
                    owner, field, offset, width, base, container, confidence,
                    assertExpr, source, line, site, func, funcAddr, funcsig, detail
            };
        }
    }

    private record Row(Proof proof) {
        Object[] cells() { return proof.cells(); }
        String field() { return proof.field(); }
        String owner() { return proof.owner(); }
    }

    public static String prove(PluginContext ctx, String address, String field, String klass,
            boolean provenOnly, int max, Page page, Map<String, String> q) {
        var hasAddress = address != null && !address.isBlank();
        var hasField = field != null && !field.isBlank();
        var hasClass = klass != null && !klass.isBlank();
        if (!hasAddress && !hasField && !hasClass) {
            throw new IllegalArgumentException(
                    "give address=<function> to prove every offset in one function, "
                            + "or field=<name> and/or class=<name> to search the assert strings program-wide");
        }
        int cap = max <= 0 ? DEFAULT_MAX : Math.min(max, MAX_FUNCTIONS);
        return ctx.withProgram(program -> {
            List<Function> targets;
            var head = new StringBuilder(512);
            if (hasAddress) {
                var a = Addresses.resolve(program, address);
                if (a == null) throw new IllegalArgumentException("invalid address: " + address);
                var f = Addresses.functionAtOrContaining(program, a);
                if (f == null) {
                    throw new IllegalArgumentException("no function at or containing " + address
                            + " (run address_context " + address + " to find out what is there)");
                }
                targets = List.of(f);
                head.append("# prove_offset function=").append(f.getName())
                    .append(" entry=").append(Responses.addr(f.getEntryPoint())).append('\n');
            } else {
                var needle = hasField ? field.trim() : klass.trim();
                targets = byString(program, needle, cap);
                head.append("# prove_offset search=").append(needle)
                    .append(" functions=").append(targets.size())
                    .append(" cap=").append(cap).append('\n');
                if (targets.isEmpty()) {
                    head.append("# no defined string mentions that name; the assert text may be an "
                            + "undefined string, try search kind=text first\n");
                    return head.toString();
                }
            }

            var rows = new ArrayList<Row>();
            for (var f : targets) {
                String c;
                try {
                    c = DecompileCache.decompile(program, f);
                } catch (RuntimeException e) {
                    continue;
                }
                for (var p : analyze(program, f, c)) rows.add(new Row(p));
            }

            var t = Responses.table(q, COLS, Math.min(page.limit(), rows.size()));
            var w = new Responses.Window(page);
            for (var r : rows) {
                if (provenOnly && !"exact".equals(r.cells()[6])) continue;
                if (hasField && !contains(r.field(), field)) continue;
                if (hasClass && !contains(r.owner(), klass)) continue;
                if (!w.take()) continue;
                t.row(r.cells());
            }
            head.append("# offset is a byte offset from base; base=param_N is the this pointer of "
                    + "the class in the class column\n");
            head.append("# confidence exact=one field and one guarded dereference; "
                    + "ambiguous=several candidates, every one listed; "
                    + "size-member=container base needs nebula_shape; "
                    + "no-guard/indirect=assert found but no offset provable\n");
            return head.append(t.total(w.total()).build()).toString();
        });
    }

    private static boolean contains(String haystack, String needle) {
        return haystack != null && haystack.toLowerCase(Locale.ROOT)
                .contains(needle.trim().toLowerCase(Locale.ROOT));
    }

    private static void rawScan(Program program, String needle, int cap,
                                LinkedHashSet<Address> seen, List<Function> out) {
        var mem = program.getMemory();
        var fm = program.getFunctionManager();
        var refs = program.getReferenceManager();
        var pat = needle.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        for (var block : mem.getBlocks()) {
            if (!block.isInitialized() || block.isExecute()) continue;
            var at = block.getStart();
            while (at != null && out.size() < cap) {
                Address hit;
                try {
                    hit = mem.findBytes(at, block.getEnd(), pat, null, true, null);
                } catch (RuntimeException e) {
                    break;
                }
                if (hit == null) break;
                for (var ref : refs.getReferencesTo(hit)) {
                    var fn = fm.getFunctionContaining(ref.getFromAddress());
                    if (fn == null || !seen.add(fn.getEntryPoint())) continue;
                    out.add(fn);
                    if (out.size() >= cap) break;
                }
                try {
                    at = hit.add(1);
                } catch (RuntimeException e) {
                    break;
                }
            }
        }
    }

    private static List<Function> byString(Program program, String needle, int cap) {
        var listing = program.getListing();
        var fm = program.getFunctionManager();
        var refs = program.getReferenceManager();
        var seen = new LinkedHashSet<Address>();
        var out = new ArrayList<Function>();
        var lower = needle.toLowerCase(Locale.ROOT);
        var it = listing.getDefinedData(true);
        while (it.hasNext() && out.size() < cap) {
            var data = it.next();
            if (data == null || !DataTypes.isStringLike(data)) continue;
            var v = data.getValue();
            if (v == null) continue;
            var sv = v.toString();
            if (!sv.toLowerCase(Locale.ROOT).contains(lower)) continue;
            for (var ref : refs.getReferencesTo(data.getAddress())) {
                var fn = fm.getFunctionContaining(ref.getFromAddress());
                if (fn == null || !seen.add(fn.getEntryPoint())) continue;
                out.add(fn);
                if (out.size() >= cap) break;
            }
        }
        if (out.isEmpty()) rawScan(program, needle, cap, seen, out);
        return out;
    }

    public static List<Proof> analyze(Program program, Function func, String c) {
        var out = new ArrayList<Proof>();
        var frame = AssertProofs.frame(c);
        var sites = AssertProofs.sites(c);
        if (sites.isEmpty()) return out;
        var siteAddr = stringSites(program, func);
        var shapeCache = new HashMap<String, NebulaShapes.Shape>();
        var budget = new int[]{SHAPE_BUDGET};
        var funcAddr = Responses.addr(func.getEntryPoint());
        for (var site : sites) {
            var owner = AssertProofs.ownerOf(site.sig());
            var fields = AssertProofs.fieldsOf(site.expr());
            var guard = AssertProofs.guardFor(c, site.start());
            var at = siteAddr.get(site.expr());
            var siteText = at == null ? "" : Responses.addr(at);
            if (fields.isEmpty()) continue;
            if (guard == null) {
                for (var f : fields) {
                    out.add(row(owner, f, "", "", "", "", "no-guard",
                            site, siteText, func, funcAddr,
                            "assert is not the first statement of an if body, so no compare anchors it"));
                }
                continue;
            }
            var derefs = new ArrayList<AssertProofs.Deref>();
            for (var d : AssertProofs.derefs(guard, frame, site.start())) {
                if (d.resolved()) derefs.add(d);
            }
            if (derefs.isEmpty()) {
                for (var f : fields) {
                    out.add(row(owner, f, "", "", "", "", "indirect",
                            site, siteText, func, funcAddr,
                            "guard " + trim(guard) + " dereferences nothing this pass can resolve"));
                }
                continue;
            }
            boolean unique = fields.size() == 1 && derefs.size() == 1;
            for (var f : fields) {
                boolean isSize = site.expr().contains(f + ".Size()");
                for (var d : derefs) {
                    var shape = isSize ? shapeFor(program, func, c, guard, shapeCache, budget) : null;
                    long offset = d.offset();
                    var container = "";
                    var confidence = unique ? "exact" : "ambiguous";
                    var detail = unique ? "" : fields.size() + " field(s) x " + derefs.size()
                            + " dereference(s) in guard " + trim(guard);
                    if (isSize && shape != null && shape.sizeOff() >= 0) {
                        container = shape.kind();
                        offset = d.offset() - shape.sizeOff();
                        detail = ("Size() load at " + AssertProofs.hex(d.offset()) + " minus "
                                + shape.kind() + " size@" + AssertProofs.hex(shape.sizeOff())
                                + "; elements at +" + AssertProofs.hex(shape.elemsOff()) + " " + detail).trim();
                    } else if (isSize) {
                        confidence = unique ? "size-member" : "ambiguous";
                        detail = ("offset is the inlined Size() load, which equals the container base "
                                + "only for Util::FixedArray; run nebula_shape on the accessor to settle it "
                                + detail).trim();
                    }
                    out.add(row(owner, f, AssertProofs.hex(offset),
                            d.width() > 0 ? Integer.toString(d.width()) : "",
                            d.base(), container, confidence, site, siteText, func, funcAddr, detail));
                }
            }
        }
        return out;
    }

    private static Proof row(String owner, String field, String offset, String width, String base,
            String container, String confidence, AssertProofs.Site site, String siteAddr,
            Function func, String funcAddr, String detail) {
        return new Proof(owner, field, offset, width, base, container, confidence,
                site.expr(), site.file(), AssertProofs.hex(site.line()), siteAddr,
                func.getName(), funcAddr, site.sig(), detail);
    }

    private static NebulaShapes.Shape shapeFor(Program program, Function func, String c, String guard,
            Map<String, NebulaShapes.Shape> cache, int[] budget) {
        var vars = new LinkedHashSet<String>();
        var sv = STAR_VAR.matcher(guard);
        while (sv.find()) vars.add(sv.group(1));
        var bv = BASE_VAR.matcher(guard);
        while (bv.find()) vars.add(bv.group(1));
        if (vars.isEmpty()) return null;
        var callees = new LinkedHashMap<String, Function>();
        for (var callee : func.getCalledFunctions(new ConsoleTaskMonitor())) {
            callees.putIfAbsent(callee.getName(), callee);
        }
        for (var v : vars) {
            var call = Pattern.compile("([A-Za-z_][A-Za-z0-9_]*)\\s*\\(\\s*" + Pattern.quote(v) + "\\s*[,)]");
            var m = call.matcher(c);
            while (m.find()) {
                var name = m.group(1);
                if (cache.containsKey(name)) {
                    var hit = cache.get(name);
                    if (hit != null) return hit;
                    continue;
                }
                var callee = callees.get(name);
                if (callee == null) {
                    cache.put(name, null);
                    continue;
                }
                if (budget[0] <= 0) return null;
                budget[0]--;
                NebulaShapes.Shape found = null;
                try {
                    var cc = DecompileCache.decompile(program, callee);
                    for (var s : AssertProofs.sites(cc)) {
                        var shape = NebulaShapes.byEvidence(s.expr(), s.file());
                        if (shape != null && shape.sizeOff() >= 0) {
                            found = shape;
                            break;
                        }
                    }
                } catch (RuntimeException e) {
                    found = null;
                }
                cache.put(name, found);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static Map<String, Address> stringSites(Program program, Function func) {
        var map = new HashMap<String, Address>();
        var listing = program.getListing();
        var it = listing.getInstructions(func.getBody(), true);
        while (it.hasNext()) {
            var ins = it.next();
            for (var ref : ins.getReferencesFrom()) {
                var d = listing.getDataAt(ref.getToAddress());
                if (d == null || !DataTypes.isStringLike(d)) continue;
                var v = d.getValue();
                if (v == null) continue;
                map.putIfAbsent(v.toString(), ins.getAddress());
            }
        }
        return map;
    }

    private static String trim(String s) {
        var t = s.replace('\n', ' ').replaceAll("\\s+", " ").trim();
        return t.length() <= 120 ? t : t.substring(0, 117) + "...";
    }
}
