package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.Http;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class RecoveryHandlers {

    private final PluginContext ctx;

    public RecoveryHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    public void register(RouteTable routes) {
        routes.postForm("/analyze_program", p -> analyzeProgram(Http.parseIntOrDefault(p.get("all"), 0) != 0));
        routes.getQuery("/list_analyzers", this::listAnalyzers);
        routes.postForm("/set_analysis_option", p -> setAnalysisOption(p.get("name"),
                Http.parseIntOrDefault(p.get("enabled"), 1) != 0));
        routes.postForm("/apply_data_type", p -> applyDataType(p.get("address"), p.get("type"),
                Http.parseIntOrDefault(p.get("clear"), 1) != 0));
        routes.postForm("/create_function", p -> createFunction(p.get("address")));
        routes.postForm("/propagate_function_types", p -> propagateTypes(p.get("function_address")));
        routes.postForm("/struct_set_field", p -> structSetField(p.get("struct"),
                Http.parseIntOrDefault(p.get("offset"), -1), p.get("type"),
                p.getOrDefault("name", ""), p.getOrDefault("mode", "replace")));
        routes.postForm("/struct_delete_field", p -> structDeleteField(p.get("struct"),
                Http.parseIntOrDefault(p.get("offset"), -1)));
    }

    private String analyzeProgram(boolean all) {
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var mgr = AutoAnalysisManager.getAnalysisManager(program);
        if (all) mgr.reAnalyzeAll(null);
        int tx = program.startTransaction(all ? "Reanalyze all" : "Analyze program");
        boolean ok = false;
        try {
            mgr.startAnalysis(new ConsoleTaskMonitor());
            ok = true;
        } finally {
            program.endTransaction(tx, ok);
        }
        return (all ? "reanalyzed" : "analyzed") + " " + program.getName();
    }

    private String listAnalyzers(Map<String, String> q) {
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        var names = options.getLeafOptionNames();
        var t = Responses.table(q, new String[]{"option", "enabled"}, names.size());
        for (var name : names) {
            t.row(name, options.getBoolean(name, false));
        }
        return t.total(names.size()).build();
    }

    private String setAnalysisOption(String name, boolean enabled) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("name is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var ok = ctx.runOnSwingTx(program, "Set analysis option", () -> {
            program.getOptions(Program.ANALYSIS_PROPERTIES).setBoolean(name, enabled);
            return true;
        });
        if (!ok) throw new IllegalStateException("Failed to set " + name);
        return name + " = " + enabled;
    }

    private String applyDataType(String addr, String type, boolean clear) {
        if (addr == null || addr.isBlank() || type == null || type.isBlank()) {
            throw new IllegalArgumentException("address and type are required");
        }
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var out = new String[1];
        var ok = ctx.runOnSwingTx(program, "Apply data type", () -> {
            var a = Addresses.parse(program, addr);
            if (a == null) { out[0] = "invalid address: " + addr; return false; }
            var dt = DataTypes.resolveDataType(program.getDataTypeManager(), type);
            if (dt == null) { out[0] = "unknown type: " + type; return false; }
            var cmd = new CreateDataCmd(a, clear, dt);
            if (!cmd.applyTo(program)) { out[0] = cmd.getStatusMsg(); return false; }
            out[0] = "applied " + dt.getName() + " at " + addr;
            return true;
        });
        if (!ok) throw new IllegalStateException(out[0] != null ? out[0] : "Failed");
        return out[0];
    }

    private String createFunction(String addr) {
        if (addr == null || addr.isBlank()) throw new IllegalArgumentException("address is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var out = new String[1];
        var ok = ctx.runOnSwingTx(program, "Create function", () -> {
            var a = Addresses.parse(program, addr);
            if (a == null) { out[0] = "invalid address: " + addr; return false; }
            var existing = program.getFunctionManager().getFunctionAt(a);
            if (existing != null) { out[0] = "function already exists: " + existing.getName(); return true; }
            var cmd = new CreateFunctionCmd(a);
            if (!cmd.applyTo(program, new ConsoleTaskMonitor())) { out[0] = cmd.getStatusMsg(); return false; }
            var f = program.getFunctionManager().getFunctionAt(a);
            out[0] = "created " + (f != null ? f.getName() : "function") + " at " + addr;
            return true;
        });
        if (!ok) throw new IllegalStateException(out[0] != null ? out[0] : "Failed");
        return out[0];
    }

    private String propagateTypes(String addr) {
        if (addr == null || addr.isBlank()) throw new IllegalArgumentException("function_address is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var a = Addresses.parse(program, addr);
        if (a == null) throw new IllegalArgumentException("invalid address: " + addr);
        var func = Addresses.functionAtOrContaining(program, a);
        if (func == null) throw new IllegalArgumentException("No function at " + addr);

        var decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            var results = decomp.decompileFunction(func, DecompileHandlers.DECOMPILE_TIMEOUT_SEC, new ConsoleTaskMonitor());
            if (results == null || !results.decompileCompleted()) throw new IllegalStateException("Decompilation failed");
            var high = results.getHighFunction();
            if (high == null) throw new IllegalStateException("Decompilation failed (no high function)");
            var ok = ctx.runOnSwingTx(program, "Propagate types", () -> {
                try {
                    HighFunctionDBUtil.commitParamsToDatabase(high, true, ReturnCommitOption.COMMIT, SourceType.ANALYSIS);
                    HighFunctionDBUtil.commitLocalNamesToDatabase(high, SourceType.ANALYSIS);
                    return true;
                } catch (Exception e) {
                    Msg.error(ctx.logOwner(), "propagateTypes commit failed", e);
                    return false;
                }
            });
            if (!ok) throw new IllegalStateException("Failed to commit types");
            return "propagated decompiler types for " + func.getName();
        } finally {
            decomp.dispose();
        }
    }

    private Structure findStruct(Program program, String name) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("struct name is required");
        var dt = DataTypes.findDataType(program.getDataTypeManager(), name);
        if (dt == null) throw new IllegalArgumentException("unknown type: " + name);
        if (!(dt instanceof Structure s)) throw new IllegalArgumentException(name + " is not a structure");
        return s;
    }

    private String structSetField(String struct, int offset, String type, String fieldName, String mode) {
        if (offset < 0) throw new IllegalArgumentException("offset must be >= 0");
        if (type == null || type.isBlank()) throw new IllegalArgumentException("type is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var out = new String[1];
        var ok = ctx.runOnSwingTx(program, "Set struct field", () -> {
            var s = findStruct(program, struct);
            var dtm = program.getDataTypeManager();
            var dt = DataTypes.resolveDataType(dtm, type);
            if (dt == null) { out[0] = "unknown type: " + type; return false; }
            int len = dt.getLength() > 0 ? dt.getLength() : 1;
            var nm = fieldName == null || fieldName.isBlank() ? null : fieldName;
            if ("insert".equals(mode)) {
                s.insertAtOffset(offset, dt, len, nm, null);
            } else {
                s.replaceAtOffset(offset, dt, len, nm, null);
            }
            out[0] = mode + " " + dt.getName() + " at +" + offset + " in " + s.getName()
                    + " (size=" + s.getLength() + ")";
            return true;
        });
        if (!ok) throw new IllegalStateException(out[0] != null ? out[0] : "Failed");
        return out[0];
    }

    private String structDeleteField(String struct, int offset) {
        if (offset < 0) throw new IllegalArgumentException("offset must be >= 0");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var out = new String[1];
        var ok = ctx.runOnSwingTx(program, "Delete struct field", () -> {
            var s = findStruct(program, struct);
            s.deleteAtOffset(offset);
            out[0] = "deleted field at +" + offset + " in " + s.getName() + " (size=" + s.getLength() + ")";
            return true;
        });
        if (!ok) throw new IllegalStateException(out[0] != null ? out[0] : "Failed");
        return out[0];
    }
}
