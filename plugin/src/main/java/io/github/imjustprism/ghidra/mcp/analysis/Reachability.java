package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public final class Reachability {

    public static final int DEFAULT_DEPTH = 6;
    public static final int MAX_DEPTH = 24;
    public static final int DEFAULT_MAX = 400;

    private static final String[] COLS = {
            "kind", "addr", "func", "section", "ref_type", "depth", "note"
    };

    private Reachability() {}

    private record Classified(String kind, Reference ref, String section, String note) {}

    public static String analyze(PluginContext ctx, String target, int depth, int max,
            Map<String, String> q) {
        int d = depth <= 0 ? DEFAULT_DEPTH : Math.min(depth, MAX_DEPTH);
        int cap = max <= 0 ? DEFAULT_MAX : max;
        if (target == null || target.isBlank()) {
            throw new IllegalArgumentException("target (function name or address) is required");
        }
        return ctx.withProgram(program -> {
            var func = Addresses.resolveFunction(program, target);
            if (func == null) {
                throw new IllegalArgumentException("no function named or at " + target
                        + " (run address_context " + target + " to see what is there)");
            }
            var direct = classify(program, func);
            int selfUnwind = 0;
            int calls = 0;
            int vtable = 0;
            int dataTable = 0;
            int crtInit = 0;
            int other = 0;
            for (var c : direct) {
                switch (c.kind()) {
                    case "self_unwind" -> selfUnwind++;
                    case "call" -> calls++;
                    case "vtable" -> vtable++;
                    case "crt_init" -> crtInit++;
                    case "data_table" -> dataTable++;
                    default -> other++;
                }
            }
            var rows = new ArrayList<Object[]>();
            for (var c : direct) {
                var from = c.ref().getFromAddress();
                var owner = program.getFunctionManager().getFunctionContaining(from);
                rows.add(new Object[]{"ref", Responses.addr(from),
                        owner == null ? "" : owner.getName(), c.section(),
                        c.ref().getReferenceType().getName(), 0, c.note()});
            }

            var callers = new LinkedHashMap<Address, Integer>();
            var roots = new LinkedHashSet<Address>();
            walk(program, func, d, cap, callers, roots);
            for (var e : callers.entrySet()) {
                var f = program.getFunctionManager().getFunctionAt(e.getKey());
                if (f == null) continue;
                boolean isRoot = roots.contains(e.getKey());
                rows.add(new Object[]{isRoot ? "root" : "caller", Responses.addr(e.getKey()),
                        f.getName(), section(program, e.getKey()), "CALL", e.getValue(),
                        isRoot ? "no caller of its own once self-unwind references are ignored" : ""});
            }

            boolean selfInit = looksLikeInitializer(func);
            var verdict = verdict(calls, vtable, dataTable, crtInit, other, roots.size(),
                    callers.size(), selfInit);
            var sb = new StringBuilder(1024);
            sb.append("# reachability ").append(func.getName())
              .append(" entry=").append(Responses.addr(func.getEntryPoint())).append('\n');
            sb.append("# verdict\t").append(verdict).append('\n');
            sb.append("# refs\tcall=").append(calls).append(" vtable=").append(vtable)
              .append(" crt_init=").append(crtInit).append(" data_table=").append(dataTable)
              .append(" other=").append(other)
              .append(" self_unwind=").append(selfUnwind).append(" (ignored)\n");
            sb.append("# callers\ttransitive=").append(callers.size())
              .append(" depth<=").append(d).append(" roots=").append(roots.size()).append('\n');
            sb.append("# note\ta lone DATA reference from .pdata is the function's own "
                    + "RUNTIME_FUNCTION unwind record, never a dispatch table; it is classified "
                    + "self_unwind and excluded from every count above. CRT .CRT$XCU / atexit "
                    + "static initializers are crt_init, not dead\n");
            var t = Responses.table(q, COLS, rows.size());
            for (var r : rows) t.row(r);
            return sb.append(t.total(rows.size()).build()).toString();
        });
    }

    static String verdict(int calls, int vtable, int dataTable, int crtInit, int other, int roots,
            int callers, boolean selfAtexit) {
        if (calls == 0 && (crtInit > 0 || selfAtexit)) {
            return "crt_init; referenced from the C++ static initializer table (or the function "
                    + "itself calls atexit / Factory::Register), so it runs before main — not dead";
        }
        if (calls == 0 && vtable == 0 && dataTable == 0 && other == 0 && crtInit == 0) {
            return "unreferenced; nothing in the image references this function once its own "
                    + ".pdata unwind record is discounted, so it is never called and never stored "
                    + "in a table - dead code in this build";
        }
        if (calls == 0 && vtable > 0) {
            return "only_via_vtable; no direct call site exists, the address only appears in "
                    + vtable + " vtable slot(s), so it runs only if something constructs that class - "
                    + "run reachability on the constructor to find out whether anything does";
        }
        if (calls == 0) {
            return "data_only; no call instruction targets this function, it is only referenced from "
                    + "data (" + (dataTable + other) + " site(s)) - inspect those with address_context "
                    + "before concluding it is dispatched";
        }
        if (callers == 0) {
            return "called; " + calls + " call site(s) reference it";
        }
        return "called; " + calls + " call site(s), " + callers + " transitive caller(s), "
                + roots + " of which have no caller of their own";
    }

    private static List<Classified> classify(Program program, Function func) {
        var out = new ArrayList<Classified>();
        var entry = func.getEntryPoint();
        var it = program.getReferenceManager().getReferencesTo(entry);
        while (it.hasNext()) {
            var ref = it.next();
            var from = ref.getFromAddress();
            var section = section(program, from);
            var type = ref.getReferenceType();
            if (Unwind.inPdata(program, from)) {
                var e = Unwind.entryAt(program, from);
                if (e != null && e.beginRva() == Unwind.rva(program, entry)) {
                    out.add(new Classified("self_unwind", ref, section,
                            "own RUNTIME_FUNCTION begin=" + Long.toHexString(e.beginRva())
                                    + " end=" + Long.toHexString(e.endRva()) + "; not a code reference"));
                    continue;
                }
                out.add(new Classified("pdata_other", ref, section,
                        "inside .pdata but not this function's own unwind record; inspect by hand"));
                continue;
            }
            if (type.isCall()) {
                out.add(new Classified("call", ref, section, "call site"));
                continue;
            }
            if (type.isJump()) {
                out.add(new Classified("call", ref, section, "tail jump / thunk"));
                continue;
            }
            if (isCrtSection(section) || looksLikeCrtSlot(program, from, func)) {
                out.add(new Classified("crt_init", ref, section,
                        "C++ static initializer slot (.CRT$XCU / rdata function-pointer run "
                                + "into an atexit or Factory::Register thunk)"));
                continue;
            }
            if (looksLikeVtable(program, from)) {
                out.add(new Classified("vtable", ref, section,
                        "slot in a run of code pointers, i.e. a vtable or a jump table"));
                continue;
            }
            out.add(new Classified("data_table", ref, section,
                    "data reference; neighbours are not all code pointers"));
        }
        return out;
    }

    static boolean isCrtSection(String name) {
        if (name == null || name.isBlank()) return false;
        var n = name.toUpperCase();
        return n.startsWith(".CRT") || n.contains("CRT$") || n.contains(".CRT");
    }

    static boolean looksLikeCrtSlot(Program program, Address from, Function target) {
        if (!looksLikeVtable(program, from) && !isRdataOrData(program, from)) return false;
        return looksLikeInitializer(target);
    }

    static boolean isRdataOrData(Program program, Address a) {
        var b = program.getMemory().getBlock(a);
        if (b == null) return false;
        var n = b.getName();
        if (n == null) return false;
        var lower = n.toLowerCase();
        return lower.contains("rdata") || lower.equals(".data") || lower.startsWith(".data");
    }

    static boolean looksLikeInitializer(Function func) {
        if (callsAtexit(func)) return true;
        var name = func.getName();
        if (name != null && (name.contains("dynamic_initializer") || name.contains("dynamic_atexit")
                || name.contains("??__E") || name.contains("??__F"))) {
            return true;
        }
        try {
            for (var callee : func.getCalledFunctions(new ghidra.util.task.ConsoleTaskMonitor())) {
                var n = callee.getName();
                if (n == null) continue;
                if (n.contains("Factory_Register") || n.contains("Rtti_Construct")
                        || n.contains("AttributeDefinitionBase_Register")
                        || n.contains("Factory::Register") || n.contains("Rtti::Construct")) {
                    return true;
                }
            }
        } catch (RuntimeException e) {
            return false;
        }
        return false;
    }

    static boolean callsAtexit(Function func) {
        try {
            for (var callee : func.getCalledFunctions(new ghidra.util.task.ConsoleTaskMonitor())) {
                var n = callee.getName();
                if (n != null && (n.equals("atexit") || n.endsWith("_atexit")
                        || n.contains("atexit"))) {
                    return true;
                }
            }
        } catch (RuntimeException e) {
            return false;
        }
        return false;
    }

    private static boolean looksLikeVtable(Program program, Address slot) {
        int hits = 0;
        for (int i = -2; i <= 2; i++) {
            if (i == 0) continue;
            try {
                var at = slot.add((long) i * 8);
                long v = program.getMemory().getLong(at);
                if (v == 0) continue;
                var target = program.getAddressFactory().getDefaultAddressSpace().getAddress(v);
                var b = program.getMemory().getBlock(target);
                if (b != null && b.isExecute()) hits++;
            } catch (Exception e) {
                return hits >= 2;
            }
        }
        return hits >= 2;
    }

    private static void walk(Program program, Function root, int depth, int cap,
            Map<Address, Integer> out, java.util.Set<Address> roots) {
        var seen = new LinkedHashSet<Address>();
        seen.add(root.getEntryPoint());
        var queue = new ArrayDeque<Address>();
        var level = new LinkedHashMap<Address, Integer>();
        queue.add(root.getEntryPoint());
        level.put(root.getEntryPoint(), 0);
        while (!queue.isEmpty() && out.size() < cap) {
            var cur = queue.poll();
            int lvl = level.getOrDefault(cur, 0);
            if (lvl >= depth) continue;
            var f = program.getFunctionManager().getFunctionAt(cur);
            if (f == null) continue;
            var parents = callersOf(program, f);
            if (parents.isEmpty() && lvl > 0) roots.add(cur);
            for (var p : parents) {
                if (!seen.add(p)) continue;
                out.put(p, lvl + 1);
                level.put(p, lvl + 1);
                queue.add(p);
                if (out.size() >= cap) break;
            }
        }
        for (var e : out.entrySet()) {
            var f = program.getFunctionManager().getFunctionAt(e.getKey());
            if (f != null && callersOf(program, f).isEmpty()) roots.add(e.getKey());
        }
    }

    private static List<Address> callersOf(Program program, Function f) {
        var out = new ArrayList<Address>();
        var seen = new LinkedHashSet<Address>();
        var it = program.getReferenceManager().getReferencesTo(f.getEntryPoint());
        while (it.hasNext()) {
            var ref = it.next();
            var from = ref.getFromAddress();
            if (Unwind.inPdata(program, from)) continue;
            if (!ref.getReferenceType().isCall() && !ref.getReferenceType().isJump()) continue;
            var owner = program.getFunctionManager().getFunctionContaining(from);
            if (owner == null || owner.getEntryPoint().equals(f.getEntryPoint())) continue;
            if (seen.add(owner.getEntryPoint())) out.add(owner.getEntryPoint());
        }
        return out;
    }

    private static String section(Program program, Address a) {
        var b = program.getMemory().getBlock(a);
        return b == null ? "" : b.getName();
    }
}
