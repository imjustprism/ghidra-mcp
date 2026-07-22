package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class FormatStringVulns {

    private static final Map<String, Integer> FMT_ARG = Map.ofEntries(
            Map.entry("printf", 0), Map.entry("wprintf", 0), Map.entry("vprintf", 0), Map.entry("vwprintf", 0),
            Map.entry("fprintf", 1), Map.entry("fwprintf", 1), Map.entry("vfprintf", 1), Map.entry("sprintf", 1),
            Map.entry("swprintf", 1), Map.entry("vsprintf", 1), Map.entry("vswprintf", 1), Map.entry("syslog", 1),
            Map.entry("snprintf", 2), Map.entry("_snprintf", 2), Map.entry("sprintf_s", 2), Map.entry("swprintf_s", 2),
            Map.entry("vsnprintf", 2), Map.entry("scanf", 0), Map.entry("sscanf", 1), Map.entry("fscanf", 1));

    private static final String[] ARG_REGS = {"RCX", "RDX", "R8", "R9"};
    private static final int BACK_SCAN = 20;

    private FormatStringVulns() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var fm = program.getFunctionManager();
            var st = program.getSymbolTable();
            var t = Responses.table(p, q, new String[]{"site", "caller", "callee", "fmt_arg", "verdict"});
            var w = new Responses.Window(p);
            for (var insn : program.getListing().getInstructions(true)) {
                for (var ref : insn.getReferencesFrom()) {
                    if (!ref.getReferenceType().isCall()) continue;
                    var callee = calleeName(program, ref.getToAddress());
                    if (callee == null) continue;
                    var argIdx = FMT_ARG.get(stripDecorations(callee));
                    if (argIdx == null || argIdx >= ARG_REGS.length) continue;
                    if (constantFormat(program, insn, ARG_REGS[argIdx])) continue;
                    if (!w.take()) continue;
                    var fn = fm.getFunctionContaining(insn.getAddress());
                    t.row(Responses.addr(insn.getAddress()), fn == null ? "" : fn.getName(),
                            callee, ARG_REGS[argIdx], "NON-CONSTANT format (potential CWE-134)");
                }
            }
            return "# format-string sites with a non-constant format argument (potential CWE-134)\n"
                    + t.total(w.total()).build();
        });
    }

    private static String calleeName(Program program, ghidra.program.model.address.Address to) {
        if (to.isExternalAddress()) {
            var s = program.getSymbolTable().getPrimarySymbol(to);
            return s == null ? null : s.getName();
        }
        var fn = program.getFunctionManager().getFunctionAt(to);
        if (fn == null) return null;
        if (fn.isThunk()) {
            var thunked = fn.getThunkedFunction(true);
            if (thunked != null) return thunked.getName();
        }
        return fn.getName();
    }

    private static String stripDecorations(String name) {
        var n = name;
        while (n.startsWith("_") || n.startsWith("@")) n = n.substring(1);
        int at = n.indexOf('@');
        if (at > 0) n = n.substring(0, at);
        return n;
    }

    private static boolean constantFormat(Program program, Instruction call, String regName) {
        var target = program.getRegister(regName);
        if (target == null) return false;
        var base = target.getBaseRegister();
        var ins = call;
        for (int i = 0; i < BACK_SCAN; i++) {
            ins = ins.getPrevious();
            if (ins == null) return false;
            for (var ro : ins.getResultObjects()) {
                if (!(ro instanceof Register r) || !base.equals(r.getBaseRegister())) continue;
                if (!ins.getMnemonicString().equalsIgnoreCase("LEA")) return false;
                for (var ref : ins.getReferencesFrom()) {
                    var data = program.getListing().getDataContaining(ref.getToAddress());
                    if (data != null && DataTypes.isStringLike(data)) return true;
                }
                return false;
            }
        }
        return false;
    }
}
