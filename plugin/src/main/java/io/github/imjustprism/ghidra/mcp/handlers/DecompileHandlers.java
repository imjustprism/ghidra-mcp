package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.program.model.listing.CodeUnit;
import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.Bufs;
import io.github.imjustprism.ghidra.mcp.util.DecompileCache;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Programs;
import io.github.imjustprism.ghidra.mcp.util.Responses;

public final class DecompileHandlers {

    public static final int DECOMPILE_TIMEOUT_SEC = DecompileCache.TIMEOUT_SEC;

    private final PluginContext ctx;

    public DecompileHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    public void register(RouteTable routes) {
        routes.getQuery("/decompile_function", q -> decompileAt(q.get("address")));
        routes.getQuery("/disassemble_function", q -> disassembleAt(q.get("address")));
        routes.getQuery("/instruction_at", q -> instructionAt(q.get("address")));
        routes.postRaw("/decompile", this::decompileByName);
    }

    public String decompileByName(String name) {
        return ctx.withProgram(program -> {
            if (name == null || name.isBlank()) throw new IllegalArgumentException("Function name is required");
            var func = Programs.findFunctionByName(program, name.trim());
            return func == null ? "Function not found" : DecompileCache.decompile(program, func);
        });
    }

    public String decompileAt(String addr) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            return func == null
                    ? "No function at or containing " + addr
                    : DecompileCache.decompile(program, func);
        });
    }

    public String disassembleAt(String addr) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) return "No function at or containing " + addr;
            var listing = program.getListing();
            var end = func.getBody().getMaxAddress();
            var sb = new StringBuilder(4096);
            sb.append("# format=tsv; addr=hex; cols=addr,instr,cmt\n");
            var instrs = listing.getInstructions(func.getEntryPoint(), true);
            while (instrs.hasNext()) {
                var instr = instrs.next();
                if (instr.getAddress().compareTo(end) > 0) break;
                var comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                sb.append(Responses.addr(instr.getAddress())).append('\t')
                  .append(Responses.cell(instr.toString())).append('\t');
                if (comment != null) sb.append(Responses.cell(comment));
                sb.append('\n');
            }
            return sb.toString();
        });
    }

    public String instructionAt(String addr) {
        return ctx.withAddress(addr, (program, a) -> {
            var instr = program.getListing().getInstructionAt(a);
            if (instr == null) return "No instruction at " + addr;
            var buf = new byte[instr.getLength()];
            try {
                program.getMemory().getBytes(a, buf, 0, buf.length);
            } catch (Exception e) {
                Msg.warn(ctx.logOwner(), "read instruction bytes at " + addr + " failed", e);
            }
            var comment = program.getListing().getComment(CodeUnit.EOL_COMMENT, a);
            var sb = new StringBuilder(64);
            sb.append(Responses.addr(instr.getAddress())).append('\t')
              .append(Bufs.hex(buf)).append('\t')
              .append(instr);
            if (comment != null) sb.append('\t').append(comment);
            return sb.toString();
        });
    }
}
