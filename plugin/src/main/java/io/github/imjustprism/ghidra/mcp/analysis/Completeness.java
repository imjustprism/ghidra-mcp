package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Map;

public final class Completeness {

    private static final int NAME_WEIGHT = 30;
    private static final int SIG_WEIGHT = 25;
    private static final int PARAMS_WEIGHT = 20;
    private static final int COMMENT_WEIGHT = 15;
    private static final int LOCALS_WEIGHT = 10;

    private static final String[] DEFAULT_VAR_PREFIXES = {
        "param_", "local_", "in_", "unaff_", "extraout_", "aStack", "auStack",
        "aiStack", "uStack", "iStack", "cVar", "uVar", "iVar", "bVar", "sVar",
        "lVar", "fVar", "dVar", "pVar", "uRam", "unique0x"
    };

    private Completeness() {}

    public static int score(Function f) {
        int s = 0;
        if (!Responses.isAutoName(f.getName())) s += NAME_WEIGHT;
        if (hasUserSignature(f)) s += SIG_WEIGHT;
        if (paramsNamed(f)) s += PARAMS_WEIGHT;
        if (hasComment(f)) s += COMMENT_WEIGHT;
        if (localsNamed(f)) s += LOCALS_WEIGHT;
        return s;
    }

    public static String single(PluginContext ctx, String addr, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var f = Addresses.functionAtOrContaining(program, a);
            if (f == null) throw new IllegalArgumentException("No function at " + addr);
            var t = Responses.table(q, new String[]{"k", "v"}, 8);
            t.row("fn", f.getName());
            t.row("entry", Responses.addr(f.getEntryPoint()));
            t.row("score", score(f));
            t.row("named", !Responses.isAutoName(f.getName()));
            t.row("typed_sig", hasUserSignature(f));
            t.row("params_named", paramsNamed(f));
            t.row("commented", hasComment(f));
            t.row("locals_named", localsNamed(f));
            return t.build();
        });
    }

    public static String findUndocumented(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var rows = new ArrayList<Object[]>();
            for (var f : program.getFunctionManager().getFunctions(true)) {
                if (f.isThunk() || f.isExternal()) continue;
                rows.add(new Object[]{score(f), f.getName(), Responses.addr(f.getEntryPoint())});
            }
            rows.sort(Comparator.comparingInt(r -> (Integer) r[0]));
            var t = Responses.table(p, q, new String[]{"score", "fn", "addr"});
            var w = new Responses.Window(p);
            for (var r : rows) {
                if (!w.take()) continue;
                t.row(r);
            }
            return t.total(w.total()).build();
        });
    }

    private static boolean hasUserSignature(Function f) {
        var src = f.getSignatureSource();
        return src == SourceType.USER_DEFINED || src == SourceType.IMPORTED;
    }

    private static boolean hasComment(Function f) {
        var c = f.getComment();
        return c != null && !c.isBlank();
    }

    private static boolean paramsNamed(Function f) {
        var params = f.getParameters();
        if (params.length == 0) return true;
        for (var p : params) {
            if (isDefaultVarName(p.getName())) return false;
        }
        return true;
    }

    private static boolean localsNamed(Function f) {
        var locals = f.getLocalVariables();
        if (locals.length == 0) return true;
        for (var v : locals) {
            if (!isDefaultVarName(v.getName())) return true;
        }
        return false;
    }

    private static boolean isDefaultVarName(String name) {
        if (name == null || name.isBlank()) return true;
        for (var prefix : DEFAULT_VAR_PREFIXES) {
            if (name.startsWith(prefix)) return true;
        }
        return false;
    }
}
