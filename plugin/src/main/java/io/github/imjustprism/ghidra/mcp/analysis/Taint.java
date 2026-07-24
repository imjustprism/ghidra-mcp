package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.handlers.DecompileHandlers;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public final class Taint {

    private static final int MAX_REACHED = 500;

    private Taint() {}

    public static String slice(PluginContext ctx, String addrStr, boolean forward, Page p, Map<String, String> q) {
        return ctx.withAddress(addrStr, (program, addr) -> {
            var func = program.getFunctionManager().getFunctionContaining(addr);
            if (func == null) throw new IllegalArgumentException("no function contains " + addrStr);
            var decomp = new DecompInterface();
            try {
                decomp.openProgram(program);
                decomp.setSimplificationStyle("decompile");
                var results = decomp.decompileFunction(func, DecompileHandlers.DECOMPILE_TIMEOUT_SEC,
                        new ConsoleTaskMonitor());
                var high = results != null && results.decompileCompleted() ? results.getHighFunction() : null;
                if (high == null) throw new IllegalStateException("decompilation failed for " + func.getName());

                var queue = new ArrayDeque<ghidra.program.model.pcode.Varnode>();
                var used = addr;
                String snap = "";
                int seedOps = seed(high, used, forward, queue);
                if (seedOps == 0) {
                    var nearest = nearestModeled(high, addr);
                    if (nearest != null && !nearest.equals(addr)) {
                        used = nearest;
                        seedOps = seed(high, used, forward, queue);
                        snap = "; snapped to nearest modeled op " + Responses.addr(used);
                    }
                }
                if (seedOps == 0) {
                    return "# no p-code operations at or near " + Responses.addr(addr) + " in "
                            + func.getName() + " (the decompiler models no instruction here)";
                }
                if (queue.isEmpty()) {
                    return "# instruction at " + Responses.addr(addr) + " has no "
                            + (forward ? "output value to slice forward (e.g. a store, branch, or void call)"
                                       : "input values to slice backward") + "; nothing to trace";
                }

                var visited = new HashSet<ghidra.program.model.pcode.Varnode>();
                var reached = new LinkedHashMap<Address, String>();
                var stops = new LinkedHashSet<String>();
                while (!queue.isEmpty() && reached.size() < MAX_REACHED) {
                    var vn = queue.poll();
                    if (!visited.add(vn)) continue;
                    if (forward) {
                        for (var it = vn.getDescendants(); it.hasNext(); ) {
                            var op = it.next();
                            record(program, op, reached);
                            if (op.getOpcode() == PcodeOp.STORE) noteMemory(program, op, stops);
                            if (op.getOutput() != null) queue.add(op.getOutput());
                        }
                    } else {
                        var def = vn.getDef();
                        if (def != null) {
                            record(program, def, reached);
                            if (def.getOpcode() == PcodeOp.LOAD) noteMemory(program, def, stops);
                            for (var in : def.getInputs()) {
                                if (in != null) queue.add(in);
                            }
                        }
                    }
                }

                boolean capped = !queue.isEmpty();
                var t = Responses.table(p, q, new String[]{"address", "instruction"});
                var w = new Responses.Window(p);
                for (var e : reached.entrySet()) {
                    if (!w.take()) continue;
                    t.row(Responses.addr(e.getKey()), Responses.cell(e.getValue()));
                }
                return "# taint " + (forward ? "forward" : "backward") + " from " + Responses.addr(used)
                        + " in " + func.getName() + " (intra-procedural; def-use only, not followed through memory"
                        + snap
                        + (capped ? "; capped at " + MAX_REACHED : "")
                        + (stops.isEmpty() ? "" : "; stops at memory: " + String.join(", ", stops)) + ")\n"
                        + t.total(w.total()).build();
            } finally {
                decomp.dispose();
            }
        });
    }

    private static int seed(ghidra.program.model.pcode.HighFunction high, Address addr, boolean forward,
                            ArrayDeque<ghidra.program.model.pcode.Varnode> queue) {
        int n = 0;
        for (var it = high.getPcodeOps(addr); it.hasNext(); ) {
            var op = it.next();
            n++;
            if (forward) {
                if (op.getOutput() != null) queue.add(op.getOutput());
            } else {
                for (var in : op.getInputs()) {
                    if (in != null) queue.add(in);
                }
            }
        }
        return n;
    }

    private static Address nearestModeled(ghidra.program.model.pcode.HighFunction high, Address addr) {
        Address best = null;
        long bestDist = Long.MAX_VALUE;
        for (var it = high.getPcodeOps(); it.hasNext(); ) {
            var target = it.next().getSeqnum().getTarget();
            if (target == null) continue;
            long dist = Math.abs(target.getOffset() - addr.getOffset());
            if (dist < bestDist) {
                bestDist = dist;
                best = target;
            }
        }
        return best;
    }

    private static void noteMemory(Program program, PcodeOp op, Set<String> stops) {
        var ptr = op.getInput(1);
        if (ptr == null || !ptr.isAddress()) return;
        var sym = program.getSymbolTable().getPrimarySymbol(ptr.getAddress());
        if (sym != null) stops.add(sym.getName());
    }

    private static void record(Program program, PcodeOp op, Map<Address, String> reached) {
        var target = op.getSeqnum().getTarget();
        if (target == null) return;
        reached.computeIfAbsent(target, a -> {
            var ins = program.getListing().getInstructionAt(a);
            return ins != null ? ins.toString() : op.getMnemonic();
        });
    }
}
