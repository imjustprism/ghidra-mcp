package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.Deadline;
import io.github.imjustprism.ghidra.mcp.util.DecompileCache;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Reconstruct a C++ SDK from the engine's own debug metadata.
 *
 * <p>Nebula3 debug builds carry {@code __FUNCSIG__} in every {@code n_assert},
 * which means the binary ships ~21k complete C++ member signatures: return type,
 * fully qualified name, parameter types and constness. Each signature string is
 * referenced from the body of the method it describes, so a signature whose
 * string is referenced by exactly one function pins that method to an address.
 *
 * <p>Joining that against {@link NebulaClassGraph} — which recovers
 * {@code sizeof} and the parent link from {@code Core::Rtti::Construct} — yields
 * a class table complete enough to re-declare the engine's API in headers you can
 * compile against.
 *
 * <p>Nothing here decompiles: it reads defined strings and cross-references only,
 * so a whole-program export is seconds rather than hours.
 */
public final class SdkExport {

    private static final String[] COLS =
            {"class", "method", "ret", "params", "qualifiers", "addr", "refs", "parent", "size", "fourcc"};

    private SdkExport() {}

    /** Default ceiling on functions decompiled for {@code fields_prove=1}. */
    public static final int DEFAULT_FIELD_MAX = 300;

    /** Default ceiling per class, so a wide filter still reaches every class. */
    public static final int DEFAULT_FIELD_PER_CLASS = 12;

    /**
     * One proven data member: the byte offset and width come from the compare
     * that guards the {@code n_assert} naming the field, never from a guess.
     */
    public record Field(long offset, String name, String width, String container,
                        String confidence, String assertExpr) {}

    /** One recovered member function. */
    public record Method(String klass, String name, String ret, String params,
                         boolean isConst, boolean isStatic, String addr, int refs) {

        /** {@code const}/{@code static} rendered for a header, or empty. */
        public String qualifiers() {
            if (isStatic && isConst) return "static const";
            if (isStatic) return "static";
            return isConst ? "const" : "";
        }
    }

    public static String export(PluginContext ctx, String filter, Page page, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var methods = collect(program);
            if (methods.isEmpty()) {
                return "# no __cdecl signature strings found — this does not look like a "
                        + "Nebula3 debug build.\n";
            }

            var classes = NebulaClassGraph.entries(program);
            var parentOf = NebulaClassGraph.parentMap(classes);
            var meta = new LinkedHashMap<String, NebulaClassGraph.Entry>();
            for (var e : classes) meta.putIfAbsent(e.klass(), e);

            var wanted = filter == null ? "" : filter.trim().toLowerCase(Locale.ROOT);
            var byClass = new TreeMap<String, List<Method>>(String.CASE_INSENSITIVE_ORDER);
            for (var m : methods) {
                if (!wanted.isEmpty() && !m.klass().toLowerCase(Locale.ROOT).contains(wanted)) continue;
                byClass.computeIfAbsent(m.klass(), k -> new ArrayList<>()).add(m);
            }
            for (var list : byClass.values()) {
                list.sort(Comparator.comparing(Method::name, String.CASE_INSENSITIVE_ORDER));
            }

            var fmt = q == null ? null : q.get("fmt");
            if ("header".equalsIgnoreCase(fmt) || "cpp".equalsIgnoreCase(fmt)) {
                boolean templates = q != null && "1".equals(q.get("templates"));
                var scan = wantsFields(q)
                        ? proveFields(program, byClass, fieldMax(q),
                                fieldPerClass(q, byClass.size()))
                        : null;
                return header(byClass, meta, parentOf, methods.size(), classes.size(),
                        templates, scan);
            }
            return index(byClass, meta, parentOf, methods.size(), classes.size(), page, q);
        });
    }

    // -----------------------------------------------------------------------
    // recovery
    // -----------------------------------------------------------------------

    /**
     * Parse every {@code __FUNCSIG__} string and pin it to a function.
     *
     * <p>A signature referenced from exactly one function names that function. A
     * signature referenced from several is an inlined assert quoting its caller's
     * signature, so the address is left blank rather than guessed — the method is
     * still real and still belongs in the header.
     */
    private static List<Method> collect(Program program) {
        var out = new ArrayList<Method>();
        for (var hit : NebulaStrings.defined(program, NebulaAssertNamer::isCdeclSignature)) {
            var m = parse(hit.value());
            if (m == null) continue;
            var refs = NebulaStrings.referrers(program, hit.addr());
            var addr = refs.size() == 1 ? Responses.addr(refs.get(0).getEntryPoint()) : "";
            out.add(new Method(m.klass(), m.name(), m.ret(), m.params(),
                    m.isConst(), m.isStatic(), addr, refs.size()));
        }
        return out;
    }

    private static boolean wantsFields(Map<String, String> q) {
        if (q == null) return false;
        var v = q.get("fields_prove");
        return "1".equals(v) || "true".equalsIgnoreCase(v);
    }

    private static int fieldMax(Map<String, String> q) {
        return intParam(q, "field_max", DEFAULT_FIELD_MAX);
    }

    /**
     * Per-class ceiling. The default only exists to stop one class eating a
     * whole-program budget, so when the filter already picked out a handful of
     * classes, spend the budget on them rather than rationing it.
     */
    private static int fieldPerClass(Map<String, String> q, int classCount) {
        int explicit = intParam(q, "field_per_class", -1);
        if (explicit > 0) return explicit;
        return classCount <= 4 ? Integer.MAX_VALUE : DEFAULT_FIELD_PER_CLASS;
    }

    private static int intParam(Map<String, String> q, String key, int fallback) {
        if (q == null) return fallback;
        var raw = q.get(key);
        if (raw == null || raw.isBlank()) return fallback;
        try {
            int n = Integer.parseInt(raw.trim());
            return n <= 0 ? fallback : n;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    /**
     * Prove data members for the selected classes.
     *
     * <p>{@code prove_offset} normally hunts for asserting functions by string
     * search. Here we already know which functions belong to a class — the
     * signature strings resolved them — so decompile those directly and keep the
     * proofs the assert attributes back to the same class.
     *
     * <p>Decompilation is the expensive step, so this is opt-in and capped; the
     * caller is told how much of the budget was spent.
     */
    private static FieldScan proveFields(Program program,
                                         Map<String, List<Method>> byClass,
                                         int budget, int perClass) {
        var out = new LinkedHashMap<String, List<Field>>();
        int spent = 0;
        int scanned = 0;
        boolean exhausted = false;
        for (var e : byClass.entrySet()) {
            if (spent >= budget) {
                exhausted = true;
                break;
            }
            var klass = e.getKey();
            scanned++;
            // Spend the budget evenly: a class's members are normally asserted by
            // its first handful of methods, so decompiling all 200 of one class
            // starves every class after it.
            int here = 0;
            // offset -> field, so repeated proofs of the same member collapse and
            // the better-supported one wins.
            var best = new TreeMap<Long, Field>();
            for (var m : e.getValue()) {
                if (spent >= budget || here >= perClass) break;
                if (m.addr().isEmpty()) continue;
                here++;
                var fn = Addresses.functionAtOrContaining(program,
                        Addresses.resolve(program, m.addr()));
                if (fn == null) continue;
                spent++;
                String c;
                try {
                    c = Deadline.call("sdk_export decompile " + m.addr(), 20,
                            () -> DecompileCache.decompile(program, fn));
                } catch (RuntimeException ex) {
                    continue;
                }
                for (var p : ProveOffset.analyze(program, fn, c)) {
                    var f = toField(p, klass);
                    if (f == null) continue;
                    var prev = best.get(f.offset());
                    if (prev == null || rank(f.confidence()) > rank(prev.confidence())) {
                        best.put(f.offset(), f);
                    }
                }
            }
            if (!best.isEmpty()) out.put(klass, new ArrayList<>(best.values()));
        }
        return new FieldScan(out, spent, scanned, byClass.size(), exhausted);
    }

    /**
     * Outcome of a field pass. Carries the budget accounting so an exhausted
     * budget is never mistaken for a class that genuinely has no proven members.
     */
    private record FieldScan(Map<String, List<Field>> byClass, int decompiled,
                             int classesScanned, int classesTotal, boolean exhausted) {}

    /**
     * Keep a proof only when the assert attributes it to the class we are
     * emitting — an inlined assert quotes its own class, not the caller's.
     */
    private static Field toField(ProveOffset.Proof p, String klass) {
        if (p.offset() == null || p.offset().isBlank()) return null;
        if (p.owner() == null || !sameClass(p.owner(), klass)) return null;
        long off;
        try {
            var raw = p.offset().trim();
            off = raw.startsWith("0x") || raw.startsWith("0X")
                    ? Long.parseLong(raw.substring(2), 16)
                    : Long.parseLong(raw);
        } catch (NumberFormatException e) {
            return null;
        }
        return new Field(off, p.field(), p.width(), p.container(),
                p.confidence(), p.assertExpr());
    }

    private static boolean sameClass(String owner, String klass) {
        var a = owner.trim();
        var b = klass.trim();
        return a.equalsIgnoreCase(b) || a.endsWith("::" + b) || b.endsWith("::" + a);
    }

    private static int rank(String confidence) {
        if (confidence == null) return 0;
        return switch (confidence) {
            case "exact" -> 3;
            case "size-member" -> 2;
            case "ambiguous" -> 1;
            default -> 0;
        };
    }

    /**
     * Best available type for a member.
     *
     * <p>A resolved container shape wins. Failing that, {@code size-member} still
     * tells us the field is a container even when the shape pass could not settle
     * which one, and that is worth more than the width of the {@code Size()} load.
     * Otherwise fall back to an integer of the access width — which is the width
     * of the dereference, not necessarily of the member.
     */
    private static String typeForWidth(String width, String container, String confidence) {
        if (container != null && !container.isBlank()) return container;
        if ("size-member".equals(confidence)) return "Util::FixedArray<>";
        if (width == null) return "void*";
        return switch (width.trim()) {
            case "1" -> "uint8_t";
            case "2" -> "uint16_t";
            case "4" -> "uint32_t";
            case "8" -> "uint64_t";
            default -> "void*";
        };
    }

    /**
     * Split {@code "class Util::Id<class Game::GameItem> __cdecl
     * Game::Inventory::GetItemAtStorageSlot(int) const"} into its parts.
     */
    static Method parse(String sig) {
        if (sig == null) return null;
        int paren = NebulaAssertNamer.indexOfTopLevel(sig, '(');
        if (paren <= 0) return null;

        var head = sig.substring(0, paren).trim();
        var tail = sig.substring(paren);
        int close = matchingParen(tail);
        if (close < 0) return null;
        var params = clean(tail.substring(1, close).trim());
        var after = tail.substring(close + 1);
        boolean isConst = after.contains("const");

        head = stripAccess(head);
        boolean isStatic = head.startsWith("static ");
        if (isStatic) head = head.substring("static ".length()).trim();

        int cc = callConv(head);
        if (cc < 0) return null;
        var ret = clean(head.substring(0, cc).trim());
        var qualified = head.substring(cc).trim();
        // drop the calling convention token itself
        int sp = qualified.indexOf(' ');
        if (sp < 0) return null;
        qualified = qualified.substring(sp + 1).trim();
        qualified = qualified.replace("class ", "").replace("struct ", "").trim();

        int split = lastTopLevelScope(qualified);
        if (split <= 0) return null;
        var klass = qualified.substring(0, split);
        var name = qualified.substring(split + 2);
        if (klass.isBlank() || name.isBlank()) return null;

        // __FUNCSIG__ never spells "static" — it is not part of a function's type.
        // Nebula's singleton accessor is recognisable by shape instead: Instance()
        // takes nothing and hands back a pointer to its own class.
        if (!isStatic && "Instance".equals(name) && "void".equals(params)
                && ret.endsWith("*") && ret.startsWith(klass)) {
            isStatic = true;
        }
        return new Method(klass, name, ret, params, isConst, isStatic, "", 0);
    }

    private static String stripAccess(String s) {
        for (var a : new String[]{"public: ", "protected: ", "private: "}) {
            if (s.startsWith(a)) return s.substring(a.length()).trim();
        }
        return s;
    }

    private static int callConv(String head) {
        for (var c : new String[]{"__cdecl", "__thiscall", "__stdcall", "__fastcall"}) {
            int i = head.indexOf(c);
            if (i >= 0) return i;
        }
        return -1;
    }

    /** MSVC spells out {@code class}/{@code struct}/{@code enum}; C++ does not need it. */
    private static String clean(String type) {
        if (type == null || type.isEmpty()) return "";
        return type.replace("class ", "").replace("struct ", "").replace("enum ", "").trim();
    }

    /** Index of the closing paren matching the {@code '('} at index 0 of {@code s}. */
    private static int matchingParen(String s) {
        int depth = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '(') depth++;
            else if (c == ')' && --depth == 0) return i;
        }
        return -1;
    }

    /**
     * Index of the last {@code ::} outside any template argument list.
     *
     * <p>Scanning left to right and keeping the last depth-0 hit also does the
     * right thing for {@code Foo::operator<}, whose unmatched {@code '<'} would
     * otherwise swallow the rest of the name.
     */
    private static int lastTopLevelScope(String s) {
        int depth = 0;
        int last = -1;
        for (int i = 0; i + 1 < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '<') depth++;
            else if (c == '>') depth = Math.max(0, depth - 1);
            else if (c == ':' && s.charAt(i + 1) == ':' && depth == 0) {
                last = i;
                i++;
            }
        }
        return last;
    }

    // -----------------------------------------------------------------------
    // rendering
    // -----------------------------------------------------------------------

    private static String index(Map<String, List<Method>> byClass,
                                Map<String, NebulaClassGraph.Entry> meta,
                                Map<String, String> parentOf,
                                int totalMethods, int totalClasses,
                                Page page, Map<String, String> q) {
        var sb = new StringBuilder(8192);
        sb.append("# sdk_export methods=").append(totalMethods)
          .append(" classes_with_methods=").append(byClass.size())
          .append(" rtti_classes=").append(totalClasses).append('\n');
        sb.append("# from __FUNCSIG__ strings joined to Core::Rtti::Construct; "
                + "addr is set when exactly one function references the signature\n");
        sb.append("# fmt=header emits C++ declarations; filter=Game::Inventory narrows\n");

        var rows = new ArrayList<Object[]>();
        for (var e : byClass.entrySet()) {
            var info = meta.get(e.getKey());
            var parent = parentOf.getOrDefault(e.getKey(), "");
            var size = info != null && info.size() > 0 ? "0x" + Long.toHexString(info.size()) : "";
            var fourcc = info != null ? info.fourcc() : "";
            for (var m : e.getValue()) {
                rows.add(new Object[]{e.getKey(), m.name(), m.ret(), m.params(),
                        m.qualifiers(), m.addr(), m.refs(), parent, size, fourcc});
            }
        }
        var t = Responses.table(page, q, COLS);
        var w = new Responses.Window(page);
        for (var r : rows) {
            if (!w.take()) continue;
            t.row(r);
        }
        sb.append(t.total(w.total()).build());
        return sb.toString();
    }

    private static String header(Map<String, List<Method>> byClass,
                                 Map<String, NebulaClassGraph.Entry> meta,
                                 Map<String, String> parentOf,
                                 int totalMethods, int totalClasses, boolean templates,
                                 FieldScan scan) {
        var fields = scan == null ? Map.<String, List<Field>>of() : scan.byClass();
        var sb = new StringBuilder(1 << 16);
        sb.append("// Reconstructed from dro_client64 debug metadata (__FUNCSIG__ + Core::Rtti::Construct).\n");
        sb.append("// methods=").append(totalMethods)
          .append(" classes_with_methods=").append(byClass.size())
          .append(" rtti_classes=").append(totalClasses).append('\n');
        sb.append("// Declarations only: offsets marked /* +0x.. */ are proven, sizes come from\n");
        sb.append("// the Rtti initialiser. Bodies are not recovered — bind by address.\n");
        if (scan != null) {
            sb.append("// Members are proven from the n_assert guarding each this->field; only\n");
            sb.append("// members some assert actually names appear, so a class is rarely complete.\n");
            sb.append("// Compare the last offset against sizeof to see what is still missing.\n");
            sb.append("// Member types are inferred from the width of the dereference, so an\n");
            sb.append("// integer type means \"read this many bytes here\", not a declared type.\n");
            sb.append("// fields: decompiled ").append(scan.decompiled())
              .append(" function(s) across ").append(scan.classesScanned())
              .append(" of ").append(scan.classesTotal()).append(" class(es)");
            if (scan.exhausted()) {
                sb.append(" — BUDGET EXHAUSTED, later classes were not scanned; raise field_max");
            }
            sb.append(".\n");
            sb.append("// A class with no members listed was scanned and proved none, unless the\n");
            sb.append("// budget line above says it was never reached.\n");
        } else {
            sb.append("// Members omitted — pass fields_prove=1 to recover them (decompiles, slower).\n");
        }
        sb.append('\n');

        int skipped = 0;
        for (var e : byClass.entrySet()) {
            var klass = e.getKey();
            // Core::Ptr<Foo> / Util::Array<Foo> instantiations are library
            // internals, and "class Ptr<Foo> {" is not a declaration you can
            // compile. Keep them out unless asked for.
            if (!templates && simpleName(klass).indexOf('<') >= 0) {
                skipped++;
                continue;
            }
            var info = meta.get(klass);
            var parent = parentOf.getOrDefault(klass, "");

            sb.append("// ").append("=".repeat(70)).append('\n');
            sb.append("// ").append(klass);
            if (info != null && info.size() > 0) {
                sb.append("   sizeof=0x").append(Long.toHexString(info.size()))
                  .append(" (").append(info.size()).append(')');
            }
            if (info != null && !info.fourcc().isEmpty()) {
                sb.append("   fourcc=").append(info.fourcc());
            }
            sb.append('\n');
            if (info != null && !info.rtti().isEmpty()) {
                sb.append("// rtti=").append(info.rtti()).append('\n');
            }

            var simple = simpleName(klass);
            sb.append("class ").append(simple);
            if (!parent.isEmpty()) sb.append(" : public ").append(parent);
            sb.append(" {\n");

            var members = fields.get(klass);
            if (members != null && !members.isEmpty()) {
                long last = 0;
                for (var f : members) {
                    sb.append("    /* +0x").append(String.format("%04X", f.offset())).append(" */ ")
                      .append(typeForWidth(f.width(), f.container(), f.confidence())).append(' ')
                      .append(f.name()).append(';');
                    sb.append("   // ").append(f.confidence());
                    if (f.assertExpr() != null && !f.assertExpr().isBlank()) {
                        sb.append(" — \"").append(f.assertExpr()).append('"');
                    }
                    sb.append('\n');
                    last = Math.max(last, f.offset());
                }
                if (info != null && info.size() > last) {
                    sb.append("    // ... unproven up to sizeof 0x")
                      .append(Long.toHexString(info.size())).append('\n');
                }
                sb.append('\n');
            }
            sb.append("public:\n");
            for (var m : e.getValue()) {
                sb.append("    ");
                if (m.isStatic()) sb.append("static ");
                if (!m.ret().isEmpty()) sb.append(m.ret()).append(' ');
                sb.append(m.name()).append('(').append(m.params()).append(')');
                if (m.isConst()) sb.append(" const");
                sb.append(';');
                if (!m.addr().isEmpty()) {
                    sb.append("   // ").append(m.addr());
                } else if (m.refs() > 1) {
                    sb.append("   // inlined/ambiguous, ").append(m.refs()).append(" refs");
                }
                sb.append('\n');
            }
            sb.append("};\n\n");
        }
        if (skipped > 0) {
            sb.append("// ").append(skipped)
              .append(" template instantiation(s) omitted — pass templates=1 to include them.\n");
        }
        return sb.toString();
    }

    /** {@code Game::Inventory} -> {@code Inventory}, keeping template arguments intact. */
    private static String simpleName(String qualified) {
        int i = lastTopLevelScope(qualified);
        return i < 0 ? qualified : qualified.substring(i + 2);
    }
}
