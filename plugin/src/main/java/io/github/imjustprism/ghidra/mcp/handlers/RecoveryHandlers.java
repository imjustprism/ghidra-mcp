package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.Http;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.FileGuard;
import io.github.imjustprism.ghidra.mcp.util.Json;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.io.IOException;
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
        routes.postForm("/batch_apply_data_type", p -> batchApplyDataType(p.get("items")));
        routes.postForm("/create_function", p -> createFunction(p.get("address")));
        routes.postForm("/propagate_function_types", p -> propagateTypes(p.get("function_address")));
        routes.postForm("/struct_set_field", p -> structSetField(p.get("struct"),
                Http.parseIntOrDefault(p.get("offset"), -1), p.get("type"),
                p.getOrDefault("name", ""), p.getOrDefault("mode", "replace")));
        routes.postForm("/struct_delete_field", p -> structDeleteField(p.get("struct"),
                Http.parseIntOrDefault(p.get("offset"), -1)));
        routes.getQuery("/list_data_type_archives", this::listDataTypeArchives);
        routes.postForm("/apply_gdt", p -> applyGdt(p.get("path")));
        routes.postForm("/import_dwarf", p -> runAnalyzer(
                new ghidra.app.plugin.core.analysis.DWARFAnalyzer(), "DWARF import"));
        routes.postForm("/apply_fid_signatures", p -> runAnalyzer(
                new ghidra.feature.fid.analyzer.FidAnalyzer(), "FID signature application"));
        routes.getQuery("/list_open_programs", this::listOpenPrograms);
        routes.postForm("/select_program", p -> selectProgram(p.get("name")));
    }

    private String listDataTypeArchives(Map<String, String> q) {
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var ordered = new java.util.LinkedHashSet<DataTypeManager>();
        ordered.add(program.getDataTypeManager());
        var svc = ctx.service(DataTypeManagerService.class);
        if (svc != null) {
            for (var m : svc.getDataTypeManagers()) ordered.add(m);
        }
        var t = Responses.table(q, new String[]{"name", "type", "types"}, ordered.size());
        for (var m : ordered) {
            t.row(m.getName(), m.getType() != null ? m.getType().toString() : "", m.getDataTypeCount(false));
        }
        return t.total(ordered.size()).build();
    }

    private String applyGdt(String path) {
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var file = FileGuard.requireAllowedPath(ctx, path);
        if (!file.isFile()) throw new IllegalArgumentException("not a file: " + file);
        FileDataTypeManager archive;
        try {
            archive = FileDataTypeManager.openFileArchive(file, false);
        } catch (IOException e) {
            throw new IllegalStateException("failed to open GDT archive: " + e.getMessage(), e);
        }
        try {
            var types = new java.util.ArrayList<ghidra.program.model.data.DataType>();
            for (var it = archive.getAllDataTypes(); it.hasNext(); ) types.add(it.next());
            var added = new int[1];
            var ok = ctx.runOnSwingTx(program, "Apply GDT " + file.getName(), () -> {
                try {
                    var dtm = program.getDataTypeManager();
                    dtm.addDataTypes(types, DataTypeConflictHandler.DEFAULT_HANDLER, new ConsoleTaskMonitor());
                    added[0] = types.size();
                    return true;
                } catch (CancelledException e) {
                    Msg.error(ctx.logOwner(), "apply_gdt cancelled", e);
                    return false;
                }
            });
            if (!ok) throw new IllegalStateException("apply_gdt failed or was cancelled; no types were merged");
            return "Applied " + added[0] + " data type(s) from " + file.getName()
                    + " (archive: " + archive.getName() + ")";
        } finally {
            archive.close();
        }
    }

    private String runAnalyzer(ghidra.app.services.Analyzer analyzer, String label) {
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        if (!analyzer.canAnalyze(program)) {
            return label + ": nothing to do (no applicable data in this program)";
        }
        var analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
        if (!analysisOptions.getBoolean(analyzer.getName(), analyzer.getDefaultEnablement(program))) {
            return label + ": disabled in this program's analysis options (skipped)";
        }
        var analyzerOptions = analysisOptions.getOptions(analyzer.getName());
        analyzer.registerOptions(analyzerOptions, program);
        analyzer.optionsChanged(analyzerOptions, program);
        var log = new ghidra.app.util.importer.MessageLog();
        var imported = new boolean[1];
        var error = new String[1];
        var namesBefore = snapshotFunctionNames(program);
        boolean committed = ctx.runOnSwingTx(program, label, () -> {
            try {
                imported[0] = analyzer.added(program, program.getMemory(), new ConsoleTaskMonitor(), log);
                return true;
            } catch (Exception e) {
                error[0] = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                Msg.error(ctx.logOwner(), label + " failed", e);
                return false;
            }
        });
        if (error[0] != null) {
            throw new IllegalStateException(label + " failed: " + error[0]);
        }
        if (!committed) {
            throw new IllegalStateException(label + " did not complete (transaction was not committed)");
        }
        long renamed = countRenamedFunctions(program, namesBefore);
        var summary = label + (imported[0] ? " ran" : " ran but reported no work") + " on "
                + program.getName() + "; renamed " + renamed + " function(s)";
        return log.hasMessages() ? summary + "\n" + log : summary;
    }

    private java.util.Map<ghidra.program.model.address.Address, String> snapshotFunctionNames(Program program) {
        var names = new java.util.HashMap<ghidra.program.model.address.Address, String>();
        for (var f : program.getFunctionManager().getFunctions(true)) {
            names.put(f.getEntryPoint(), f.getName());
        }
        return names;
    }

    private long countRenamedFunctions(Program program,
            java.util.Map<ghidra.program.model.address.Address, String> before) {
        long n = 0;
        for (var f : program.getFunctionManager().getFunctions(true)) {
            var prev = before.get(f.getEntryPoint());
            if (prev == null) {
                if (f.getSymbol().getSource() != SourceType.DEFAULT) n++;
            } else if (!prev.equals(f.getName())) {
                n++;
            }
        }
        return n;
    }

    private String listOpenPrograms(Map<String, String> q) {
        var pm = ctx.service(ProgramManager.class);
        if (pm == null) throw new IllegalStateException("Program manager not available");
        var current = pm.getCurrentProgram();
        var all = pm.getAllOpenPrograms();
        var t = Responses.table(q, new String[]{"name", "current", "sha256", "path"}, all.length);
        for (var p : all) {
            var sha = p.getExecutableSHA256();
            var path = p.getExecutablePath();
            t.row(p.getName(), p == current, sha != null ? sha : "", path != null ? path : "");
        }
        return t.total(all.length).build();
    }

    private String selectProgram(String name) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("name is required");
        var pm = ctx.service(ProgramManager.class);
        if (pm == null) throw new IllegalStateException("Program manager not available");
        var matches = new java.util.ArrayList<Program>();
        for (var p : pm.getAllOpenPrograms()) {
            if (p.getName().equals(name) || name.equals(p.getExecutableSHA256())) matches.add(p);
        }
        if (matches.isEmpty()) throw new IllegalArgumentException("no open program matches: " + name);
        if (matches.size() > 1) {
            throw new IllegalArgumentException(
                    "ambiguous: " + matches.size() + " open programs match '" + name + "'; use the exact sha256");
        }
        var chosen = matches.get(0);
        var ok = ctx.runOnSwing(() -> {
            pm.setCurrentProgram(chosen);
            return true;
        });
        if (!ok) throw new IllegalStateException("failed to switch to " + chosen.getName());
        return "selected " + chosen.getName();
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

    private String batchApplyDataType(String itemsJson) {
        if (itemsJson == null || itemsJson.isBlank()) throw new IllegalArgumentException("items JSON array is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var items = Json.parseObjectArray(itemsJson);
        if (items.isEmpty()) throw new IllegalArgumentException("items is empty");
        var report = new StringBuilder("# result\taddress\tdetail\n");
        var okCount = new int[1];
        ctx.runOnSwingTx(program, "Batch apply data type", () -> {
            var dtm = program.getDataTypeManager();
            for (var it : items) {
                var addr = it.get("address");
                try {
                    var type = it.get("type");
                    if (type == null || type.isBlank()) throw new IllegalArgumentException("type is required");
                    var a = Addresses.parse(program, addr);
                    if (a == null) throw new IllegalArgumentException("invalid address");
                    var dt = DataTypes.resolveDataType(dtm, type);
                    if (dt == null) throw new IllegalArgumentException("unknown type: " + type);
                    var clearVal = it.get("clear");
                    var clear = clearVal == null || !("0".equals(clearVal) || "false".equalsIgnoreCase(clearVal));
                    var cmd = new CreateDataCmd(a, clear, dt);
                    if (!cmd.applyTo(program)) throw new IllegalStateException(cmd.getStatusMsg());
                    okCount[0]++;
                    report.append("ok\t").append(Responses.cell(addr)).append('\t')
                            .append(Responses.cell(dt.getName())).append('\n');
                } catch (Exception e) {
                    report.append("fail\t").append(Responses.cell(addr)).append('\t')
                            .append(Responses.cell(e.getMessage())).append('\n');
                }
            }
            return true;
        });
        return "applied " + okCount[0] + "/" + items.size() + "\n" + report;
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
