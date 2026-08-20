package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * The Nebula3 class hierarchy, recovered from {@code Core::Rtti::Construct}.
 *
 * <p>Every {@code __ImplementClass} in a Nebula3 build emits a static
 * initialiser that constructs the class's {@code Core::Rtti} object. The engine
 * ships the signature of that constructor in its own assert string:
 *
 * <pre>
 * Core::Rtti::Construct(const char *,                              // class name
 *                       class Util::FourCC,                        // FourCC
 *                       class Core::RefCounted *(__cdecl *)(void), // factory creator
 *                       const class Core::Rtti *,                  // parent Rtti
 *                       int)                                       // sizeof(class)
 * </pre>
 *
 * <p>So each call site carries two things nothing else in the binary does: the
 * <em>parent</em> link, which gives the whole inheritance graph, and
 * <em>sizeof(class)</em>, which bounds structure recovery — you know when a
 * layout is complete instead of guessing.
 *
 * <p>This is a superset of {@code factory_catalog}: abstract bases have an Rtti
 * but are never registered with the factory, so they appear here and nowhere
 * else. Extraction reads the call site's operands directly; nothing is
 * decompiled, so it runs in seconds on a full client.
 */
public final class NebulaClassGraph {

    private static final String[] COLS = {
        "class", "fourcc", "size", "parent", "depth", "rtti", "creator"
    };

    /** Below this many callers a function is not the engine-wide Rtti hub. */
    private static final int MIN_HUB_CALLERS = 100;
    /** A class is never this big; guards against picking a stack displacement. */
    private static final long MAX_INSTANCE_SIZE = 0x100000;

    private static final Map<Program, Cached> CACHE =
            Collections.synchronizedMap(new WeakHashMap<>());

    private NebulaClassGraph() {}

    /** One recovered class. {@code parentRtti} is resolved to a name later. */
    public record Entry(String klass, String fourcc, long size, String rtti,
                        String parentRtti, String creator, String site) {}

    public static String graph(PluginContext ctx, String filter, String root, String ctorSpec,
                               Page page, Map<String, String> q) {
        return ctx.withProgram(program -> {
            if (q != null && "1".equals(q.get("refresh"))) CACHE.remove(program);
            var hub = resolveHub(program, ctorSpec);
            if (hub == null) {
                return "# could not locate Core::Rtti::Construct.\n"
                        + "# It is the function called by every __ImplementClass static "
                        + "initialiser with (name, fourcc, creator, parent, size).\n"
                        + "# Pass ctor=<address> explicitly, or check this is a Nebula3 build.\n";
            }
            var entries = collect(program, hub);
            if (entries.isEmpty()) {
                return "# " + hub.getName() + " has no decodable call sites — "
                        + "wrong hub? pass ctor=<address>\n";
            }

            var byRtti = new HashMap<String, String>();
            for (var e : entries) {
                if (!e.rtti().isEmpty()) byRtti.putIfAbsent(e.rtti(), e.klass());
            }
            var parentOf = new LinkedHashMap<String, String>();
            for (var e : entries) {
                parentOf.put(e.klass(), byRtti.getOrDefault(e.parentRtti(), ""));
            }

            var wanted = filter == null ? "" : filter.trim().toLowerCase(Locale.ROOT);
            var subtree = root == null || root.isBlank() ? null : descendants(parentOf, root.trim());

            if (q != null) {
                var fmt = q.get("fmt");
                if ("mermaid".equalsIgnoreCase(fmt) || "dot".equalsIgnoreCase(fmt)) {
                    return renderGraph(entries, parentOf, wanted, subtree, fmt);
                }
            }

            var sorted = new ArrayList<>(entries);
            sorted.sort(Comparator.comparing(Entry::klass, String.CASE_INSENSITIVE_ORDER));

            int roots = 0;
            int maxDepth = 0;
            var rows = new ArrayList<Object[]>();
            for (var e : sorted) {
                var parent = parentOf.getOrDefault(e.klass(), "");
                int depth = depthOf(parentOf, e.klass());
                if (parent.isEmpty()) roots++;
                maxDepth = Math.max(maxDepth, depth);
                if (!wanted.isEmpty() && !e.klass().toLowerCase(Locale.ROOT).contains(wanted)
                        && !parent.toLowerCase(Locale.ROOT).contains(wanted)) {
                    continue;
                }
                if (subtree != null && !subtree.contains(e.klass())) continue;
                rows.add(new Object[]{e.klass(), e.fourcc(), e.size() > 0 ? e.size() : "",
                        parent, depth, e.rtti(), e.creator()});
            }

            var sb = new StringBuilder(4096);
            sb.append("# nebula_class_graph classes=").append(entries.size())
              .append(" roots=").append(roots)
              .append(" max_depth=").append(maxDepth)
              .append(" ctor=").append(Responses.addr(hub.getEntryPoint())).append('\n');
            sb.append("# from Core::Rtti::Construct(name, fourcc, creator, parent, sizeof) — "
                    + "size bounds struct recovery; parent gives the inheritance chain\n");
            sb.append("# fmt=mermaid|dot draws the tree; root=<Class> limits to its subtree; "
                    + "filter= matches class or parent\n");
            var t = Responses.table(page, q, COLS);
            var w = new Responses.Window(page);
            for (var r : rows) {
                if (!w.take()) continue;
                t.row(r);
            }
            sb.append(t.total(w.total()).build());
            return sb.toString();
        });
    }

    // -----------------------------------------------------------------------
    // hub discovery
    // -----------------------------------------------------------------------

    private static Function resolveHub(Program program, String spec) {
        if (spec != null && !spec.isBlank()) {
            var addr = io.github.imjustprism.ghidra.mcp.util.Addresses.parse(program, spec.trim());
            if (addr != null) {
                var fn = program.getFunctionManager().getFunctionContaining(addr);
                if (fn != null) return fn;
            }
        }
        return autoDetect(program);
    }

    /**
     * Find the Rtti constructor structurally.
     *
     * <p>There is no symbol and the signature string carries no reference, so the
     * hub is identified by the shape of its call sites: a qualified class-name
     * string, a printable FourCC immediate, and two writable-data pointers (the
     * class's own Rtti and its parent's).
     */
    private static Function autoDetect(Program program) {
        Function best = null;
        int bestScore = 0;
        for (var fn : program.getFunctionManager().getFunctions(true)) {
            if (fn.isExternal() || fn.isThunk()) continue;
            List<Function> callers;
            try {
                callers = NebulaStrings.callersOf(program, fn);
            } catch (RuntimeException e) {
                continue;
            }
            if (callers.size() < MIN_HUB_CALLERS) continue;
            // Sample across the whole caller list rather than the first N: the
            // earliest callers are not representative (thunks, forwarders), which
            // made a contiguous head-sample miss the real hub entirely.
            int wanted = Math.min(40, callers.size());
            int stride = Math.max(1, callers.size() / wanted);
            int score = 0;
            int sampled = 0;
            for (int i = 0; i < callers.size() && sampled < wanted; i += stride) {
                var caller = callers.get(i);
                sampled++;
                var e = extract(program, caller, fn);
                // All four together are what makes this the Rtti constructor and
                // not merely a popular helper called with qualified names: a
                // class name, a printable FourCC, a plausible instance size, and
                // a second Rtti pointer for the parent.
                if (e != null && !e.klass().isEmpty() && !e.fourcc().isEmpty()
                        && e.size() > 0 && !e.parentRtti().isEmpty()) {
                    score++;
                }
            }
            if (score > bestScore) {
                bestScore = score;
                best = fn;
            }
        }
        // Needing all four fields together is already a strong filter — the wrong
        // hub scored zero on every sample — so a modest count is enough, and
        // being lenient here beats failing to find the hub at all.
        return bestScore >= 8 ? best : null;
    }

    // -----------------------------------------------------------------------
    // extraction
    // -----------------------------------------------------------------------

    private static List<Entry> collect(Program program, Function hub) {
        // Key on the hub too: asking for a different ctor= must not silently hand
        // back the previous one's results under the new header.
        var key = Responses.addr(hub.getEntryPoint());
        var cached = CACHE.get(program);
        if (cached != null && key.equals(cached.hub())) return cached.entries();
        var out = new ArrayList<Entry>();
        var seen = new HashSet<Address>();
        for (var caller : NebulaStrings.callersOf(program, hub)) {
            if (!seen.add(caller.getEntryPoint())) continue;
            var e = extract(program, caller, hub);
            if (e != null && !e.klass().isEmpty()) out.add(e);
        }
        CACHE.put(program, new Cached(key, out));
        return out;
    }

    private record Cached(String hub, List<Entry> entries) {}

    /**
     * Decode one {@code __ImplementClass} static initialiser.
     *
     * <p>Reads operands rather than decompiling: the two writable-data references
     * are the class's Rtti then its parent's, in argument order; the executable
     * reference is the factory creator; the printable 32-bit immediate is the
     * FourCC and the remaining small immediate is {@code sizeof}.
     */
    static Entry extract(Program program, Function init, Function hub) {
        var listing = program.getListing();
        var dataRefs = new ArrayList<String>();
        var codeRefs = new ArrayList<String>();
        var strings = new ArrayList<String>();
        var immediates = new ArrayList<Long>();
        var memory = program.getMemory();

        // Which data address ends up in RCX is the only reliable way to tell the
        // class's own Rtti from its parent's: MSVC emits the stack argument (the
        // parent, arg 5) *before* it loads RCX (this, arg 1), so reference order
        // is the reverse of argument order and cannot be trusted.
        String ownFromRcx = null;

        var it = listing.getInstructions(init.getBody(), true);
        while (it.hasNext()) {
            var ins = it.next();
            collectImmediates(ins, immediates);
            var dest = ins.getNumOperands() > 0 ? ins.getRegister(0) : null;
            boolean intoRcx = dest != null && isRcx(dest.getName());
            for (var ref : ins.getReferencesFrom()) {
                var to = ref.getToAddress();
                if (to.equals(hub.getEntryPoint())) continue;
                var data = listing.getDataAt(to);
                if (data != null && data.getValue() != null
                        && io.github.imjustprism.ghidra.mcp.util.DataTypes.isStringLike(data)) {
                    strings.add(data.getValue().toString());
                    continue;
                }
                var block = memory.getBlock(to);
                if (block == null) continue;
                if (block.isExecute()) {
                    codeRefs.add(Responses.addr(to));
                } else if (block.isWrite() || !block.isInitialized()) {
                    var s = Responses.addr(to);
                    if (intoRcx) ownFromRcx = s;
                    if (!dataRefs.contains(s)) dataRefs.add(s);
                }
            }
        }

        var klass = NebulaNames.pickClassName(strings);
        if (klass == null || klass.isEmpty()) return null;

        var fourccRaw = NebulaNames.pickFourCC(immediates);
        var fourcc = "";
        if (fourccRaw != null && !fourccRaw.isEmpty()) {
            try {
                fourcc = NebulaNames.fourCCAscii(Long.parseLong(fourccRaw.substring(2), 16));
            } catch (RuntimeException ignored) {
                fourcc = fourccRaw;
            }
        }

        long size = 0;
        for (var v : immediates) {
            if (NebulaNames.isFourCC(v)) continue;
            if (v > 0 && v < MAX_INSTANCE_SIZE && v > size) size = v;
        }

        String rtti;
        String parent;
        if (ownFromRcx != null) {
            rtti = ownFromRcx;
            parent = "";
            for (var candidate : dataRefs) {
                if (!candidate.equals(rtti)) {
                    parent = candidate;
                    break;
                }
            }
        } else {
            // No RCX load found (unusual inlining). Fall back to reference counts:
            // a base class Rtti is pointed at by every subclass, the class's own
            // is not, so the least-referenced address is the one being built.
            rtti = leastReferenced(program, dataRefs);
            parent = "";
            for (var candidate : dataRefs) {
                if (!candidate.equals(rtti)) {
                    parent = candidate;
                    break;
                }
            }
        }
        var creator = codeRefs.isEmpty() ? "" : codeRefs.get(0);
        return new Entry(klass, fourcc, size, rtti, parent, creator,
                Responses.addr(init.getEntryPoint()));
    }

    private static boolean isRcx(String register) {
        if (register == null) return false;
        var r = register.toUpperCase(Locale.ROOT);
        return r.equals("RCX") || r.equals("ECX");
    }

    /** Of these data slots, the one fewest things point at. */
    private static String leastReferenced(Program program, List<String> candidates) {
        if (candidates.isEmpty()) return "";
        String best = candidates.get(0);
        int bestCount = Integer.MAX_VALUE;
        for (var c : candidates) {
            var addr = io.github.imjustprism.ghidra.mcp.util.Addresses.parse(program, c);
            if (addr == null) continue;
            int count;
            try {
                count = program.getReferenceManager().getReferenceCountTo(addr);
            } catch (RuntimeException e) {
                continue;
            }
            if (count < bestCount) {
                bestCount = count;
                best = c;
            }
        }
        return best;
    }

    private static void collectImmediates(Instruction ins, List<Long> out) {
        for (int i = 0; i < ins.getNumOperands(); i++) {
            // Only true immediates: a memory operand's displacement (rsp+0x28)
            // would otherwise be mistaken for the instance size.
            if ((ins.getOperandType(i) & OperandType.SCALAR) == 0) continue;
            var objects = ins.getOpObjects(i);
            if (objects == null || objects.length != 1 || !(objects[0] instanceof Scalar sc)) {
                continue;
            }
            long v;
            try {
                v = sc.getUnsignedValue();
            } catch (RuntimeException e) {
                v = sc.getValue();
            }
            out.add(v);
        }
    }

    // -----------------------------------------------------------------------
    // hierarchy
    // -----------------------------------------------------------------------

    /** Distance to a root; cycle-guarded, since a bad parent decode could loop. */
    private static int depthOf(Map<String, String> parentOf, String klass) {
        int depth = 0;
        var seen = new HashSet<String>();
        var current = klass;
        while (seen.add(current)) {
            var parent = parentOf.get(current);
            if (parent == null || parent.isEmpty()) break;
            depth++;
            current = parent;
            if (depth > 64) break;
        }
        return depth;
    }

    private static HashSet<String> descendants(Map<String, String> parentOf, String root) {
        var out = new HashSet<String>();
        out.add(root);
        boolean grew = true;
        while (grew) {
            grew = false;
            for (var e : parentOf.entrySet()) {
                if (out.contains(e.getValue()) && out.add(e.getKey())) grew = true;
            }
        }
        return out;
    }

    private static String renderGraph(List<Entry> entries, Map<String, String> parentOf,
                                      String filter, HashSet<String> subtree, String fmt) {
        var sb = new StringBuilder(4096);
        boolean mermaid = "mermaid".equalsIgnoreCase(fmt);
        sb.append(mermaid ? "```mermaid\nflowchart TD\n" : "digraph nebula {\n  rankdir=TB;\n");
        int edges = 0;
        for (var e : entries) {
            var parent = parentOf.getOrDefault(e.klass(), "");
            if (parent.isEmpty()) continue;
            if (!filter.isEmpty() && !e.klass().toLowerCase(Locale.ROOT).contains(filter)
                    && !parent.toLowerCase(Locale.ROOT).contains(filter)) {
                continue;
            }
            if (subtree != null && !subtree.contains(e.klass())) continue;
            if (++edges > 800) break;
            if (mermaid) {
                sb.append("  ").append(node(parent)).append("[\"").append(parent)
                  .append("\"] --> ").append(node(e.klass())).append("[\"")
                  .append(e.klass()).append("\"]\n");
            } else {
                sb.append("  \"").append(parent).append("\" -> \"")
                  .append(e.klass()).append("\";\n");
            }
        }
        sb.append(mermaid ? "```\n" : "}\n");
        sb.append("# ").append(edges).append(" edge(s)");
        if (edges > 800) sb.append(" (capped — narrow with filter= or root=)");
        sb.append('\n');
        return sb.toString();
    }

    private static String node(String name) {
        var sb = new StringBuilder("n_");
        for (int i = 0; i < name.length() && i < 48; i++) {
            char c = name.charAt(i);
            sb.append(Character.isLetterOrDigit(c) ? c : '_');
        }
        return sb.toString();
    }
}
