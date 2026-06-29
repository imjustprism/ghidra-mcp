package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.app.plugin.assembler.AssemblySyntaxException;
import io.github.imjustprism.ghidra.mcp.util.Bufs;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.io.ByteArrayOutputStream;

public final class Assemble {

    private Assemble() {}

    public static String assemble(PluginContext ctx, String addrStr, String assembly) {
        if (assembly == null || assembly.isBlank()) throw new IllegalArgumentException("assembly is required");
        return ctx.withAddress(addrStr, (program, start) -> {
            var asm = Assemblers.getAssembler(program);
            var out = new ByteArrayOutputStream();
            var sb = new StringBuilder();
            var at = start;
            for (var raw : assembly.split("[\\r\\n;]+")) {
                var line = raw.trim();
                if (line.isEmpty()) continue;
                byte[] bytes;
                try {
                    bytes = asm.assembleLine(at, line);
                } catch (AssemblySyntaxException | AssemblySemanticException e) {
                    return "assembly failed at " + Responses.addr(at) + " on '" + line + "': " + e.getMessage();
                }
                sb.append(Responses.addr(at)).append('\t').append(line).append('\t').append(Bufs.hex(bytes)).append('\n');
                out.writeBytes(bytes);
                at = at.add(bytes.length);
            }
            var all = out.toByteArray();
            if (all.length == 0) return "no instructions assembled";
            return "# assembled " + all.length + " byte(s) at " + Responses.addr(start)
                    + " (address-relative; not written — use patch_bytes to apply)\n"
                    + "addr\tinstruction\tbytes\n" + sb + "# total: " + Bufs.hex(all) + "\n";
        });
    }
}
