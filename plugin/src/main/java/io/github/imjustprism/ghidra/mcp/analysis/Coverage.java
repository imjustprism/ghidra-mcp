package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.FileGuard;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.io.IOException;
import java.nio.file.Files;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public final class Coverage {

    private static final long MAX_LINES = 20_000_000L;

    private Coverage() {}

    public static String report(PluginContext ctx, String path, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var funcs = coveredFunctions(ctx, program, path);
            int total = program.getFunctionManager().getFunctionCount();
            var t = Responses.table(p, q, new String[]{"function", "entry"});
            var w = new Responses.Window(p);
            for (var f : funcs) {
                if (!w.take()) continue;
                t.row(f.getName(), Responses.addr(f.getEntryPoint()));
            }
            int pct = total == 0 ? 0 : (int) Math.round(100.0 * funcs.size() / total);
            return "# covered " + funcs.size() + " / " + total + " functions (" + pct + "%)\n"
                    + t.total(w.total()).build();
        });
    }

    public static String diff(PluginContext ctx, String pathA, String pathB, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var a = coveredFunctions(ctx, program, pathA);
            var b = coveredFunctions(ctx, program, pathB);
            var onlyA = new LinkedHashSet<>(a);
            onlyA.removeAll(b);
            var onlyB = new LinkedHashSet<>(b);
            onlyB.removeAll(a);
            var t = Responses.table(p, q, new String[]{"side", "function", "entry"});
            var w = new Responses.Window(p);
            for (var f : onlyA) {
                if (w.take()) t.row("a_only", f.getName(), Responses.addr(f.getEntryPoint()));
            }
            for (var f : onlyB) {
                if (w.take()) t.row("b_only", f.getName(), Responses.addr(f.getEntryPoint()));
            }
            return "# a=" + a.size() + " b=" + b.size() + " a_only=" + onlyA.size()
                    + " b_only=" + onlyB.size() + " shared=" + (a.size() - onlyA.size()) + "\n"
                    + t.total(w.total()).build();
        });
    }

    private static Set<Function> coveredFunctions(PluginContext ctx, Program program, String path) {
        var file = FileGuard.requireAllowedPath(ctx, path);
        if (!file.isFile()) throw new IllegalArgumentException("not a file: " + file);
        var fm = program.getFunctionManager();
        var af = program.getAddressFactory();
        var covered = new LinkedHashSet<Function>();
        try (var reader = Files.newBufferedReader(file.toPath())) {
            String line;
            long n = 0;
            while ((line = reader.readLine()) != null && n++ < MAX_LINES) {
                var s = line.trim();
                if (s.isEmpty() || s.startsWith("#") || s.startsWith(";")) continue;
                int sp = s.indexOf(' ');
                if (sp > 0) s = s.substring(0, sp);
                var addr = af.getAddress(s);
                if (addr == null) continue;
                var f = fm.getFunctionContaining(addr);
                if (f != null) covered.add(f);
            }
        } catch (IOException e) {
            throw new IllegalStateException("failed to read coverage file: " + e.getMessage(), e);
        }
        return covered;
    }
}
