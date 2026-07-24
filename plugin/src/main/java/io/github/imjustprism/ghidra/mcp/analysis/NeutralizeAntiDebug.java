package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.hashes.Hashes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class NeutralizeAntiDebug {

    private NeutralizeAntiDebug() {}

    public static String run(PluginContext ctx, Map<String, String> q) {
        boolean apply = "1".equals(q.get("apply")) || "0".equals(q.get("dry_run"));
        return ctx.withProgram(program -> {
            var sites = collectSites(program);
            if (!apply) {
                return render(sites, program, false, "dry_run");
            }
            boolean ok = ctx.runOnSwingTx(program, "Neutralize anti-debug", () -> {
                for (Site s : sites) patch(program, s);
                return true;
            });
            return render(sites, program, true, ok ? "patched" : "patch_failed");
        });
    }

    private static void patch(Program program, Site s) {
        try {
            var block = program.getMemory().getBlock(s.addr);
            if (block == null) return;
            boolean wasWrite = block.isWrite();
            if (!wasWrite) block.setWrite(true);
            try {
                Address end = s.addr.add(s.length - 1);
                program.getListing().clearCodeUnits(s.addr, end, false);
                byte[] buf = new byte[s.length];
                for (int i = 0; i < s.length; i++) buf[i] = (byte) 0x90;

                if (s.length >= 2) { buf[0] = 0x31; buf[1] = (byte) 0xC0; }
                program.getMemory().setBytes(s.addr, buf);
                new DisassembleCommand(s.addr, null, true)
                    .applyTo(program, new ConsoleTaskMonitor());
            } finally {
                if (!wasWrite) block.setWrite(false);
            }
        } catch (Exception e) {
            Msg.error(NeutralizeAntiDebug.class, "patch failed at " + s.addr, e);
        }
    }

    private static List<Site> collectSites(Program program) {
        var out = new ArrayList<Site>();
        var listing = program.getListing();
        var refMgr = program.getReferenceManager();
        for (Symbol sym : program.getSymbolTable().getExternalSymbols()) {
            if (!Hashes.ANTI_DEBUG_APIS.contains(sym.getName())) continue;
            ReferenceIterator it = refMgr.getReferencesTo(sym.getAddress());
            while (it.hasNext()) {
                Reference r = it.next();
                Instruction ins = listing.getInstructionAt(r.getFromAddress());
                if (ins == null) continue;
                String mn = ins.getMnemonicString().toUpperCase();
                if (!mn.equals("CALL")) continue;
                boolean inExec = false;
                MemoryBlock blk = program.getMemory().getBlock(ins.getAddress());
                if (blk != null) inExec = blk.isExecute();
                if (!inExec) continue;
                out.add(new Site(ins.getAddress(), ins.getLength(), sym.getName()));
            }
        }
        return out;
    }

    private static String render(List<Site> sites, Program program, boolean patched, String status) {
        var t = Responses.table(new java.util.HashMap<>(), new String[]{"addr", "api", "len", "status"}, sites.size());
        for (Site s : sites) t.row(Responses.addr(s.addr), s.api, s.length, status);
        return t.total(sites.size()).build();
    }

    private record Site(Address addr, int length, String api) {}
}
