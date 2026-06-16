package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Instruction;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public final class Syscalls {

    private static final int SSN_LOOKBACK = 8;

    private record Stub(String kind, String mnemonic, byte[] opcode) {}

    private static final List<Stub> STUBS = List.of(
        new Stub("syscall", "SYSCALL", new byte[]{0x0F, 0x05}),
        new Stub("sysenter", "SYSENTER", new byte[]{0x0F, 0x34}),
        new Stub("int2e", "INT", new byte[]{(byte) 0xCD, 0x2E})
    );

    private Syscalls() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var mem = program.getMemory();
            var listing = program.getListing();
            var monitor = new ConsoleTaskMonitor();
            var rows = new ArrayList<Object[]>();
            for (var stub : STUBS) {
                var mask = new byte[stub.opcode().length];
                Arrays.fill(mask, (byte) 0xFF);
                var cursor = mem.getMinAddress();
                while (cursor != null) {
                    var hit = mem.findBytes(cursor, stub.opcode(), mask, true, monitor);
                    if (hit == null) break;
                    var block = mem.getBlock(hit);
                    var insn = listing.getInstructionAt(hit);
                    if (block != null && block.isExecute() && insn != null
                            && insn.getMnemonicString().equalsIgnoreCase(stub.mnemonic())) {
                        rows.add(new Object[]{Responses.addr(hit), stub.kind(), findSsn(program, insn)});
                    }
                    cursor = hit.next();
                }
            }
            var t = Responses.table(p, q, new String[]{"addr", "kind", "ssn"});
            var w = new Responses.Window(p);
            for (var r : rows) {
                if (w.take()) t.row(r);
            }
            return t.total(w.total()).build();
        });
    }

    private static String findSsn(ghidra.program.model.listing.Program program, Instruction insn) {
        var fn = program.getFunctionManager().getFunctionContaining(insn.getAddress());
        var prev = insn.getPrevious();
        for (int i = 0; i < SSN_LOOKBACK && prev != null; i++, prev = prev.getPrevious()) {
            if (fn != null && !fn.getBody().contains(prev.getAddress())) break;
            if (!prev.getMnemonicString().equalsIgnoreCase("MOV") || prev.getNumOperands() < 2) continue;
            var reg = prev.getRegister(0);
            var scalar = prev.getScalar(1);
            if (reg != null && "EAX".equalsIgnoreCase(reg.getName()) && scalar != null) {
                return "0x" + Long.toHexString(scalar.getUnsignedValue());
            }
        }
        return "?";
    }
}
