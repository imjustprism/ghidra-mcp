package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

public final class FactoryCatalog {

    private static final String[] COLS = {
            "class", "fourcc", "fourcc_ascii", "rtti", "register", "register_addr",
            "factory", "via", "thunk", "thunk_addr"
    };

    private FactoryCatalog() {}

    public record Row(String klass, String fourcc, String fourccAscii, String rtti,
            String register, String registerAddr, String factory, String via,
            String thunk, String thunkAddr) {}

    public static String catalog(PluginContext ctx, String filter, Page page, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var rows = collect(program);
            var t = Responses.table(q, COLS, Math.min(page.limit(), rows.size()));
            var w = new Responses.Window(page);
            int kept = 0;
            for (var r : rows) {
                if (!NebulaNames.containsIgnoreCase(r.klass(), filter)
                        && !NebulaNames.containsIgnoreCase(r.fourccAscii(), filter)) {
                    continue;
                }
                kept++;
                if (!w.take()) continue;
                t.row(r.klass(), r.fourcc(), r.fourccAscii(), r.rtti(), r.register(),
                        r.registerAddr(), r.factory(), r.via(), r.thunk(), r.thunkAddr());
            }
            var sb = new StringBuilder(256);
            sb.append("# factory_catalog classes=").append(rows.size())
              .append(" shown_filter=").append(kept).append('\n');
            sb.append("# no decompile: class comes from a string xref in the static "
                    + "initializer, FourCC from a printable imm32, rtti from a writable "
                    + "data operand; via=register|construct\n");
            if (rows.isEmpty()) {
                sb.append("# no Core::Factory::Register / Core::Rtti::Construct hub found; "
                        + "run name_from_signatures first or search kind=string "
                        + "\"Core::Factory::Register\"\n");
            }
            return sb.append(t.total(w.total()).build()).toString();
        });
    }

    static List<Row> collect(Program program) {
        var hubs = new LinkedHashMap<Address, Function>();
        addHub(hubs, program, "Core::Factory::Register");
        addHub(hubs, program, "Core::Rtti::Construct");
        var seen = new LinkedHashSet<Address>();
        var rows = new ArrayList<Row>();
        for (var hub : hubs.values()) {
            for (var thunk : NebulaStrings.callersOf(program, hub)) {
                var row = extract(program, thunk, hub);
                if (row.klass().isEmpty() && thinWrapper(program, thunk)) {
                    for (var inner : NebulaStrings.callersOf(program, thunk)) {
                        if (!seen.add(inner.getEntryPoint())) continue;
                        var r = extract(program, inner, hub);
                        if (!r.klass().isEmpty()) rows.add(r);
                    }
                    continue;
                }
                if (!seen.add(thunk.getEntryPoint())) continue;
                if (!row.klass().isEmpty()) rows.add(row);
            }
        }
        rows.sort((a, b) -> a.klass().compareToIgnoreCase(b.klass()));
        return rows;
    }

    private static void addHub(Map<Address, Function> hubs, Program program, String needle) {
        var hub = NebulaStrings.pickHub(program, needle);
        if (hub != null) hubs.putIfAbsent(hub.getEntryPoint(), hub);
    }

    private static boolean thinWrapper(Program program, Function fn) {
        long size = fn.getBody().getNumAddresses();
        return size < 80 && extractClass(program, fn).isEmpty();
    }

    static Row extract(Program program, Function thunk, Function hub) {
        var strings = new ArrayList<String>();
        var immediates = new ArrayList<Long>();
        var rtti = "";
        var factory = "";
        var listing = program.getListing();
        var it = listing.getInstructions(thunk.getBody(), true);
        while (it.hasNext()) {
            var ins = it.next();
            collectImmediates(ins, immediates);
            for (var ref : ins.getReferencesFrom()) {
                var to = ref.getToAddress();
                var data = listing.getDataAt(to);
                if (data != null && data.getValue() != null
                        && io.github.imjustprism.ghidra.mcp.util.DataTypes.isStringLike(data)) {
                    strings.add(data.getValue().toString());
                    continue;
                }
                var callee = program.getFunctionManager().getFunctionAt(to);
                if (callee != null && (callee.isExternal()
                        || callee.getEntryPoint().equals(hub.getEntryPoint()))) {
                    continue;
                }
                if (callee != null && factory.isEmpty()
                        && !callee.getName().contains("Factory")
                        && !callee.getName().contains("atexit")
                        && !callee.getName().contains("ClassExists")
                        && !callee.getName().contains("Instance")
                        && !callee.getName().contains("String")
                        && !callee.getName().contains("Memory")
                        && NebulaStrings.inbound(program, callee) < 80) {
                    var blk = program.getMemory().getBlock(to);
                    if (blk != null && blk.isExecute()) factory = Responses.addr(to);
                    continue;
                }
                if (rtti.isEmpty() && isRttiSlot(program, to)) {
                    rtti = Responses.addr(to);
                }
            }
        }
        var klass = NebulaNames.pickClassName(strings);
        var fourcc = NebulaNames.pickFourCC(immediates);
        var ascii = "";
        if (!fourcc.isEmpty()) {
            try {
                ascii = NebulaNames.fourCCAscii(Long.parseLong(fourcc.substring(2), 16));
            } catch (NumberFormatException ignored) {
                ascii = "";
            }
        }
        var via = hub.getName().contains("Rtti") || hub.getName().contains("Construct")
                ? "construct" : "register";
        return new Row(klass, fourcc, ascii, rtti, hub.getName(),
                Responses.addr(hub.getEntryPoint()), factory, via,
                thunk.getName(), Responses.addr(thunk.getEntryPoint()));
    }

    private static String extractClass(Program program, Function fn) {
        return NebulaNames.pickClassName(NebulaStrings.stringsIn(program, fn));
    }

    private static void collectImmediates(Instruction ins, List<Long> out) {
        for (int i = 0; i < ins.getNumOperands(); i++) {
            var sc = ins.getScalar(i);
            if (sc != null) {
                long v = unsigned(sc);
                if (NebulaNames.isFourCC(v)) out.add(v);
            }
        }
    }

    private static long unsigned(Scalar sc) {
        try {
            return sc.getUnsignedValue();
        } catch (RuntimeException e) {
            return sc.getValue();
        }
    }

    private static boolean isRttiSlot(Program program, Address to) {
        var block = program.getMemory().getBlock(to);
        if (block == null || block.isExecute()) return false;
        if (!(block.isWrite() || !block.isInitialized())) {
            var name = block.getName();
            if (name == null || !(name.contains("bss") || name.contains("data")
                    || name.startsWith(".bss") || name.startsWith(".data"))) {
                return false;
            }
        }
        try {
            return program.getReferenceManager().getReferenceCountTo(to) <= 16;
        } catch (RuntimeException e) {
            return true;
        }
    }
}
