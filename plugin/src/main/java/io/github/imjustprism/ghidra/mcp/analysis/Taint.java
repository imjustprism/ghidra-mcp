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
import java.util.Map;

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
                int seedOps = 0;
                for (var it = high.getPcodeOps(addr); it.hasNext(); ) {
                    var op = it.next();
                    seedOps++;
                    if (forward) {
                        if (op.getOutput() != null) queue.add(op.getOutput());
                    } else {
                        for (var in : op.getInputs()) {
                            if (in != null) queue.add(in);
                        }
                    }
                }
                if (seedOps == 0) {
                    return "# no p-code operations at " + Responses.addr(addr) + " in " + func.getName()
                            + " (not a modeled instruction target; pick the address of an instruction the decompiler represents)";
                }
                if (queue.isEmpty()) {
                    return "# instruction at " + Responses.addr(addr) + " has no "
                            + (forward ? "output value to slice forward (e.g. a store, branch, or void call)"
                                       : "input values to slice backward") + "; nothing to trace";
                }

                var visited = new HashSet<ghidra.program.model.pcode.Varnode>();
                var reached = new LinkedHashMap<Address, String>();
                while (!queue.isEmpty() && reached.size() < MAX_REACHED) {
                    var vn = queue.poll();
                    if (!visited.add(vn)) continue;
                    if (forward) {
                        for (var it = vn.getDescendants(); it.hasNext(); ) {
                            var op = it.next();
                            record(program, op, reached);
                            if (op.getOutput() != null) queue.add(op.getOutput());
                        }
                    } else {
                        var def = vn.getDef();
                        if (def != null) {
                            record(program, def, reached);
                            for (var in : def.getInputs()) {
                                if (in != null) queue.add(in);
                            }
                        }
                    }
                }

                var t = Responses.table(p, q, new String[]{"address", "instruction"});
                var w = new Responses.Window(p);
                for (var e : reached.entrySet()) {
                    if (!w.take()) continue;
                    t.row(Responses.addr(e.getKey()), Responses.cell(e.getValue()));
                }
                return "# taint " + (forward ? "forward" : "backward") + " from " + Responses.addr(addr)
                        + " in " + func.getName() + " (intra-procedural; def-use only, not followed through memory"
                        + (reached.size() >= MAX_REACHED ? "; capped at " + MAX_REACHED : "") + ")\n"
                        + t.total(w.total()).build();
            } finally {
                decomp.dispose();
            }
        });
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
