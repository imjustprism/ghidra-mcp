package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.program.model.listing.CodeUnit;
import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.analysis.DecompileMinimal;
import io.github.imjustprism.ghidra.mcp.http.Http;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.Bufs;
import io.github.imjustprism.ghidra.mcp.util.DecompileCache;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

public final class DecompileHandlers {

    public static final int DECOMPILE_TIMEOUT_SEC = DecompileCache.TIMEOUT_SEC;

    private final PluginContext ctx;

    public DecompileHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    public void register(RouteTable routes) {
        routes.getQuery("/decompile", q -> decompile(q.get("target"), q.get("clean"),
                Http.parseIntOrDefault(q.get("offset"), 0), Http.parseIntOrDefault(q.get("limit"), 0),
                q.get("grep")));
        routes.getQuery("/disassemble_function", q -> disassembleAt(q.get("address")));
        routes.getQuery("/instruction_at", q -> instructionAt(q.get("address")));
    }

    public String decompile(String target, String cleanMode, int offset, int limit, String grep) {
        return ctx.withProgram(program -> {
            if (target == null || target.isBlank()) {
                throw new IllegalArgumentException("target (function name or address) is required");
            }
            var t = target.trim();
            var func = Addresses.resolveFunction(program, t);
            if (func == null) throw new IllegalArgumentException(notFound(program, t));
            var c = DecompileCache.decompile(program, func);
            c = applyClean(c, cleanMode);
            return window(c, offset, limit, grep);
        });
    }

    static String applyClean(String c, String cleanMode) {
        if (cleanMode == null || cleanMode.isBlank()) return c;
        var m = cleanMode.trim().toLowerCase(java.util.Locale.ROOT);
        return switch (m) {
            case "std", "aggressive", "2" -> DecompileMinimal.minimizeStd(c);
            case "1", "true", "yes", "on" -> DecompileMinimal.minimize(c);
            default -> c;
        };
    }

    private static String notFound(ghidra.program.model.listing.Program program, String t) {
        var base = Responses.addr(program.getImageBase());
        var a = Addresses.resolve(program, t);
        if (a == null) {
            return "no function named or at " + t + " (image_base=" + base + "; if " + t
                    + " is an RVA, prefix it rva:)";
        }
        return "no function named or at " + t + " (resolved " + Responses.addr(a)
                + ", image_base=" + base + "; that address is not inside a defined function)";
    }

    private static String window(String c, int offset, int limit, String grep) {
        boolean paged = offset > 0 || limit > 0;
        boolean filtered = grep != null && !grep.isBlank();
        if (!paged && !filtered) return c;
        java.util.regex.Pattern pat = null;
        if (filtered) {
            try {
                pat = java.util.regex.Pattern.compile(grep);
            } catch (java.util.regex.PatternSyntaxException e) {
                throw new IllegalArgumentException("bad grep regex: " + e.getMessage());
            }
        }
        var lines = c.split("\n", -1);
        int from = Math.max(0, offset);
        int cap = limit > 0 ? limit : Integer.MAX_VALUE;
        var sb = new StringBuilder(Math.min(c.length(), 16384));
        int shown = 0;
        int matched = 0;
        for (int i = 0; i < lines.length; i++) {
            if (pat != null && !pat.matcher(lines[i]).find()) continue;
            matched++;
            if (matched <= from || shown >= cap) continue;
            sb.append(i + 1).append('\t').append(lines[i]).append('\n');
            shown++;
        }
        sb.append("# lines=").append(shown).append('/').append(matched);
        if (filtered) sb.append(" matching /").append(grep).append('/');
        sb.append("; total=").append(lines.length).append('\n');
        return sb.toString();
    }

    public String disassembleAt(String addr) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("No function at or containing " + addr);
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
            if (instr == null) throw new IllegalArgumentException("No instruction at " + addr);
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
