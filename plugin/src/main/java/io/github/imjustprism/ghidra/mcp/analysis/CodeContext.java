package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.Bufs;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class CodeContext {

    public static final int DEFAULT_COUNT = 4;
    public static final int MAX_COUNT = 64;
    public static final int DEFAULT_BYTES = 16;
    public static final int MAX_BYTES = 256;

    private CodeContext() {}

    public static String context(PluginContext ctx, String addr, int count, int bytes,
            Map<String, String> q) {
        int n = count <= 0 ? DEFAULT_COUNT : Math.min(count, MAX_COUNT);
        int len = bytes <= 0 ? DEFAULT_BYTES : Math.min(bytes, MAX_BYTES);
        return ctx.withAddress(addr, (program, a) -> {
            var mem = program.getMemory();
            var listing = program.getListing();
            var block = mem.getBlock(a);
            var fm = program.getFunctionManager();
            var at = fm.getFunctionAt(a);
            var containing = at != null ? at : fm.getFunctionContaining(a);
            var instr = listing.getInstructionContaining(a);
            var data = instr == null ? listing.getDataContaining(a) : null;
            var unwind = Unwind.covering(program, a);
            var selfEntry = Unwind.entryAt(program, a);

            var sb = new StringBuilder(2048);
            sb.append("# address_context ").append(Responses.addr(a)).append('\n');
            sb.append("# query\tva=").append(Responses.addr(a))
              .append(" rva=").append(Long.toHexString(Unwind.rva(program, a)))
              .append(" section=").append(block == null ? "<unmapped>" : block.getName())
              .append(" perms=").append(perms(program, a))
              .append(" image_base=").append(Responses.addr(program.getImageBase())).append('\n');

            var verdict = verdict(a, at, containing, instr, data);
            sb.append("# verdict\t").append(verdict).append('\n');

            sb.append("# function_start\t").append(at != null ? "yes" : "no");
            if (at != null) {
                sb.append(" name=").append(at.getName())
                  .append(" size=").append(at.getBody().getNumAddresses());
            } else if (containing != null) {
                sb.append(" containing=").append(containing.getName())
                  .append(" entry=").append(Responses.addr(containing.getEntryPoint()))
                  .append(" delta=+").append(Long.toHexString(a.subtract(containing.getEntryPoint())));
            } else {
                sb.append(" containing=<none>");
            }
            sb.append('\n');

            if (instr != null) {
                long delta = a.subtract(instr.getAddress());
                sb.append("# instruction\tstarts=").append(Responses.addr(instr.getAddress()))
                  .append(" len=").append(instr.getLength())
                  .append(" delta=+").append(Long.toHexString(delta))
                  .append(delta == 0 ? " aligned=yes" : " aligned=no")
                  .append(" text=").append(Responses.cell(instr.toString())).append('\n');
                sb.append("# unshifted\t").append(Responses.addr(instr.getAddress())).append('\t')
                  .append(read(program, instr.getAddress(), len)).append('\n');
            } else if (data != null) {
                sb.append("# instruction\tnone; defined data ")
                  .append(data.getDataType().getName())
                  .append(" starts=").append(Responses.addr(data.getAddress()))
                  .append(" len=").append(data.getLength())
                  .append(" delta=+").append(Long.toHexString(a.subtract(data.getAddress()))).append('\n');
            } else {
                sb.append("# instruction\tnone; address is not inside any disassembled instruction "
                        + "or defined data\n");
            }

            if (containing != null) {
                sb.append("# entry_bytes\t").append(Responses.addr(containing.getEntryPoint()))
                  .append('\t').append(read(program, containing.getEntryPoint(), len)).append('\n');
            }

            if (selfEntry != null) {
                sb.append("# pdata_slot\tthis address IS a RUNTIME_FUNCTION record: begin=")
                  .append(Long.toHexString(selfEntry.beginRva()))
                  .append(" end=").append(Long.toHexString(selfEntry.endRva()))
                  .append(" unwind=").append(Long.toHexString(selfEntry.unwindRva()))
                  .append(" -> covers ")
                  .append(Responses.addr(Unwind.owner(program, selfEntry)))
                  .append(" (unwind metadata, not a code reference)\n");
            }
            var owner = Unwind.owner(program, unwind);
            if (unwind != null && owner != null) {
                sb.append("# pdata_cover\tRUNTIME_FUNCTION begin=").append(Long.toHexString(unwind.beginRva()))
                  .append(" end=").append(Long.toHexString(unwind.endRva()))
                  .append(" unwind=").append(Long.toHexString(unwind.unwindRva()))
                  .append(" -> the exception directory says this address belongs to the function at ")
                  .append(Responses.addr(owner))
                  .append(entryAgrees(containing, owner)).append('\n');
            } else if (block != null && ".text".equalsIgnoreCase(block.getName())) {
                sb.append("# pdata_cover\tno RUNTIME_FUNCTION covers this address; "
                        + "it is either a leaf/thunk or not inside a function body\n");
            }

            var rows = window(program, a, instr, containing, n);
            var t = Responses.table(q, new String[]{"addr", "delta", "bytes", "text", "mark"}, rows.size());
            for (var r : rows) t.row(r);
            return sb.append(t.total(rows.size()).build()).toString();
        });
    }

    private static String entryAgrees(ghidra.program.model.listing.Function containing, Address owner) {
        if (containing == null) return " (Ghidra has no function there)";
        return containing.getEntryPoint().equals(owner)
                ? " (agrees with Ghidra)"
                : " (DISAGREES with Ghidra, which says " + Responses.addr(containing.getEntryPoint()) + ")";
    }

    private static String verdict(Address a, ghidra.program.model.listing.Function at,
            ghidra.program.model.listing.Function containing, Instruction instr, ghidra.program.model.listing.Data data) {
        if (at != null) {
            return "function_start; " + Responses.addr(a) + " is the entry point of " + at.getName()
                    + ", a byte window read here is aligned to the prologue";
        }
        if (instr != null && instr.getAddress().equals(a)) {
            return "instruction_start; an instruction begins here but it is NOT a function entry"
                    + (containing == null ? "" : ", it is inside " + containing.getName()
                    + " which starts at " + Responses.addr(containing.getEntryPoint()));
        }
        if (instr != null) {
            return "mid_instruction; " + Responses.addr(a) + " is "
                    + Long.toHexString(a.subtract(instr.getAddress()))
                    + " bytes INTO the instruction that starts at " + Responses.addr(instr.getAddress())
                    + " - any byte window read from here is shifted"
                    + (containing == null ? "" : "; containing function entry is "
                    + Responses.addr(containing.getEntryPoint()));
        }
        if (data != null) {
            return "data; " + Responses.addr(a) + " is inside defined data of type "
                    + data.getDataType().getName() + " starting at " + Responses.addr(data.getAddress());
        }
        return "undefined; no instruction and no defined data here"
                + (containing == null ? "" : ", though it is inside the body of " + containing.getName());
    }

    private static List<Object[]> window(Program program, Address a, Instruction instr,
            ghidra.program.model.listing.Function containing, int n) {
        var rows = new ArrayList<Object[]>();
        var listing = program.getListing();
        var anchor = instr;
        if (anchor == null && containing != null) {
            anchor = listing.getInstructionAt(containing.getEntryPoint());
        }
        if (anchor == null) return rows;
        var before = new ArrayList<Instruction>();
        var walk = anchor;
        for (int i = 0; i < n; i++) {
            walk = listing.getInstructionBefore(walk.getAddress());
            if (walk == null) break;
            before.add(0, walk);
        }
        for (var ins : before) rows.add(instrRow(program, a, ins, containing));
        rows.add(instrRow(program, a, anchor, containing));
        walk = anchor;
        for (int i = 0; i < n; i++) {
            walk = listing.getInstructionAfter(walk.getAddress());
            if (walk == null) break;
            rows.add(instrRow(program, a, walk, containing));
        }
        return rows;
    }

    private static Object[] instrRow(Program program, Address a, Instruction ins,
            ghidra.program.model.listing.Function containing) {
        var buf = new byte[ins.getLength()];
        try {
            program.getMemory().getBytes(ins.getAddress(), buf, 0, buf.length);
        } catch (Exception e) {
            buf = new byte[0];
        }
        var mark = new StringBuilder();
        long delta = ins.getAddress().subtract(a);
        if (delta == 0) {
            mark.append("<== query");
        } else if (delta < 0 && -delta < ins.getLength()) {
            mark.append("<== query is +").append(Long.toHexString(-delta))
                .append(" INTO this instruction");
        }
        if (containing != null && containing.getEntryPoint().equals(ins.getAddress())) {
            if (mark.length() > 0) mark.append(' ');
            mark.append("[function entry ").append(containing.getName()).append(']');
        }
        var comment = program.getListing().getComment(CodeUnit.EOL_COMMENT, ins.getAddress());
        var text = comment == null ? ins.toString() : ins + "  ; " + comment;
        return new Object[]{Responses.addr(ins.getAddress()),
                (delta < 0 ? "-0x" + Long.toHexString(-delta) : "+0x" + Long.toHexString(delta)),
                Bufs.hex(buf), text, mark.toString()};
    }

    private static String read(Program program, Address at, int len) {
        var buf = new byte[len];
        try {
            program.getMemory().getBytes(at, buf, 0, len);
        } catch (Exception e) {
            return "";
        }
        return Bufs.hex(buf);
    }

    private static String perms(Program program, Address a) {
        var b = program.getMemory().getBlock(a);
        if (b == null) return "";
        return (b.isRead() ? "R" : "-") + (b.isWrite() ? "W" : "-")
                + (b.isExecute() ? "X" : "-") + (b.isInitialized() ? "I" : "-");
    }
}
