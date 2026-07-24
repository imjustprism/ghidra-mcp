package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.DecompileCache;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.List;

public final class RefineHandlers {

    private static final List<String> NOISE = List.of(
            "undefined", "in_EAX", "in_ECX", "in_EDX", "unaff_", "extraout_",
            "(int)", "(uint)", "(char)", "(short)", "CONCAT", "SUB4", "SUB8", "code *", "halt_baddata");
    private static final int MAX_OUTPUT_CHARS = 60_000;

    private final PluginContext ctx;

    public RefineHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    public void register(RouteTable routes) {
        routes.postForm("/refine_function", p -> refine(p.get("address"), p.get("commit")));
    }

    private String refine(String address, String commitStr) {
        if (address == null || address.isBlank()) throw new IllegalArgumentException("address is required");
        boolean commit = commitStr == null || !commitStr.equalsIgnoreCase("false") && !"0".equals(commitStr);
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var a = program.getAddressFactory().getAddress(address.trim());
        if (a == null) throw new IllegalArgumentException("invalid address: " + address);
        var func = Addresses.functionAtOrContaining(program, a);
        if (func == null) throw new IllegalArgumentException("No function at or containing " + address);

        var decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            var before = decompile(decomp, func);
            if (before == null) throw new IllegalStateException("Decompilation failed for " + func.getName());
            int beforeScore = score(before.text);
            return applyAndMeasure(program, func, decomp, before, beforeScore, commit);
        } finally {
            decomp.dispose();
        }
    }

    private String applyAndMeasure(Program program, Function func, DecompInterface decomp,
            Decompiled before, int beforeScore, boolean commit) {
        int tx = program.startTransaction("refine_function");
        boolean keep = false;
        String after = before.text;
        int afterScore = beforeScore;
        String err = null;
        try {
            HighFunctionDBUtil.commitParamsToDatabase(before.high, true,
                    ReturnCommitOption.COMMIT_NO_VOID, SourceType.ANALYSIS);
            HighFunctionDBUtil.commitLocalNamesToDatabase(before.high, SourceType.ANALYSIS);
            var redo = decompile(decomp, func);
            if (redo != null) {
                after = redo.text;
                afterScore = score(after);
            }
            keep = commit && afterScore <= beforeScore;
        } catch (Throwable e) {
            err = describe(e);
        } finally {
            program.endTransaction(tx, keep);
        }
        if (keep) DecompileCache.clear();
        return format(func, beforeScore, afterScore, keep, commit, err, after);
    }

    private record Decompiled(String text, HighFunction high) {}

    private static Decompiled decompile(DecompInterface decomp, Function func) {
        DecompileResults r = decomp.decompileFunction(func, DecompileCache.TIMEOUT_SEC, new ConsoleTaskMonitor());
        if (r == null || !r.decompileCompleted() || r.getHighFunction() == null) return null;
        return new Decompiled(r.getDecompiledFunction().getC(), r.getHighFunction());
    }

    private static int score(String c) {
        int s = 0;
        for (var marker : NOISE) {
            int from = 0;
            while ((from = c.indexOf(marker, from)) >= 0) {
                s++;
                from += marker.length();
            }
        }
        return s;
    }

    private static String format(Function func, int before, int after, boolean keep,
            boolean commit, String err, String text) {
        var sb = new StringBuilder();
        sb.append("# refine ").append(func.getName()).append(" @")
                .append(Responses.addr(func.getEntryPoint())).append('\n');
        sb.append("noise_before=").append(before).append(" noise_after=").append(after)
                .append(" delta=").append(after - before).append('\n');
        if (err != null) sb.append("ERROR: ").append(err).append('\n');
        if (keep) {
            sb.append("KEPT: decompiler-inferred prototype + local names committed to the program.\n");
        } else if (!commit) {
            sb.append("DRY RUN (commit=false): changes reverted.\n");
        } else if (err == null) {
            sb.append("REVERTED: commit did not reduce decompiler noise; prototype left unchanged.\n");
        }
        var trimmed = text.length() > MAX_OUTPUT_CHARS
                ? text.substring(0, MAX_OUTPUT_CHARS) + "\n...[truncated]" : text;
        return sb.append("--- decompiled (").append(keep ? "after" : "current").append(") ---\n")
                .append(trimmed).toString();
    }

    private static String describe(Throwable e) {
        var sb = new StringBuilder();
        for (Throwable c = e; c != null && sb.length() < 1500; c = c.getCause()) {
            sb.append(c.getClass().getSimpleName());
            if (c.getMessage() != null) sb.append(": ").append(c.getMessage());
            sb.append(" | ");
            if (c == c.getCause()) break;
        }
        return sb.toString();
    }
}
