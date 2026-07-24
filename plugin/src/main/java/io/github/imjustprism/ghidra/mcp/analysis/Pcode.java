package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

public final class Pcode {

    private Pcode() {}

    public static String pcodeFunction(PluginContext ctx, String addr) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("No function at " + addr);
            var listing = program.getListing();
            var end = func.getBody().getMaxAddress();
            var sb = new StringBuilder(8192);
            sb.append("# format=tsv; addr=hex; cols=addr,op,in,out\n");
            var instrs = listing.getInstructions(func.getEntryPoint(), true);
            while (instrs.hasNext()) {
                var ins = instrs.next();
                if (ins.getAddress().compareTo(end) > 0) break;
                for (var op : ins.getPcode()) {
                    sb.append(Responses.addr(ins.getAddress())).append('\t')
                      .append(op.getMnemonic()).append('\t');
                    var inputs = op.getInputs();
                    for (int i = 0; i < inputs.length; i++) {
                        if (i > 0) sb.append(',');
                        sb.append(inputs[i]);
                    }
                    sb.append('\t');
                    var out = op.getOutput();
                    if (out != null) sb.append(out);
                    sb.append('\n');
                }
            }
            return sb.toString();
        });
    }
}
