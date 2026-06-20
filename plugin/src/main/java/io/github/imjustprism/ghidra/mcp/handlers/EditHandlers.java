package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.Http;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.Json;
import io.github.imjustprism.ghidra.mcp.util.NamingConvention;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Programs;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.nio.charset.StandardCharsets;
import java.util.Map;

public final class EditHandlers {

    public sealed interface PrototypeResult {
        record Ok(String warnings) implements PrototypeResult {}

        record Failed(String message) implements PrototypeResult {}
    }

    private final PluginContext ctx;

    public EditHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    public void register(RouteTable routes) {
        routes.postForm("/renameFunction", p -> require(
                renameFunction(p.get("oldName"), p.get("newName")),
                "Renamed successfully", "Rename failed (check oldName exists and newName is valid)"));
        routes.postForm("/renameData", p -> renameDataAt(p.get("address"), p.get("newName")));
        routes.postForm("/renameVariable", p -> renameVariable(p.get("functionName"), p.get("oldName"), p.get("newName")));
        routes.postForm("/set_decompiler_comment", p -> require(
                setComment(p.get("address"), p.get("comment"), CodeUnit.PRE_COMMENT, "Set decompiler comment"),
                "Comment set successfully", "Failed to set comment"));
        routes.postForm("/set_disassembly_comment", p -> require(
                setComment(p.get("address"), p.get("comment"), CodeUnit.EOL_COMMENT, "Set disassembly comment"),
                "Comment set successfully", "Failed to set comment"));
        routes.postForm("/rename_function_by_address", p -> require(
                renameFunctionAt(p.get("function_address"), p.get("new_name")),
                "Function renamed successfully", "Failed to rename function"));
        routes.postForm("/set_function_prototype", p -> {
            var r = setFunctionPrototype(p.get("function_address"), p.get("prototype"));
            return switch (r) {
                case EditHandlers.PrototypeResult.Ok(String warn) when warn.isEmpty() -> "Function prototype set successfully";
                case EditHandlers.PrototypeResult.Ok(String warn) -> "Function prototype set successfully\n\nWarnings/Debug Info:\n" + warn;
                case EditHandlers.PrototypeResult.Failed(String msg) -> throw new IllegalStateException("Failed to set function prototype: " + msg);
            };
        });
        routes.postForm("/set_local_variable_type", p -> setLocalVariableType(p.get("function_address"), p.get("variable_name"), p.get("new_type")));
        routes.postForm("/create_label", p -> require(
                createLabel(p.get("address"), p.get("name")),
                "Label created", "Failed to create label"));
        routes.postForm("/import_c_header", p -> importCHeader(p.get("header"), p.getOrDefault("category", "")));
        routes.postForm("/create_struct", p -> createStruct(p.get("name"), p.get("fields")));
        routes.postForm("/create_union", p -> createUnion(p.get("name"), p.get("fields")));
        routes.postForm("/create_enum", p -> createEnum(p.get("name"), Http.parseIntOrDefault(p.get("size"), 4), p.get("values")));
        routes.postForm("/batch_rename", p -> batchRename(p.get("items")));
        routes.postForm("/batch_set_comment", p -> batchSetComment(p.get("items")));
        routes.postForm("/batch_set_prototype", p -> batchSetPrototype(p.get("items")));
        routes.postForm("/batch_set_variable_type", p -> batchSetVariableType(p.get("items")));
        routes.postForm("/set_variables", p -> setVariables(p.get("function_address"),
                p.get("new_name"), p.get("prototype"), p.get("variables")));
        routes.postForm("/apply_naming_convention", p -> applyNamingConvention(p.get("convention"),
                p.get("namespace"), Http.parseIntOrDefault(p.get("apply"), 0) != 0));
    }

    private static final int MAX_PREVIEW = 500;

    public String applyNamingConvention(String conventionName, String namespace, boolean apply) {
        var convention = NamingConvention.from(conventionName);
        if (convention == null) {
            throw new IllegalArgumentException("convention must be one of: snake, screaming_snake, camel, pascal");
        }
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var nsFilter = namespace == null || namespace.isBlank() ? null : namespace.trim();

        record Change(String address, String oldName, String newName, Function function) {}
        var changes = new java.util.ArrayList<Change>();
        for (var f : program.getFunctionManager().getFunctions(true)) {
            if (f.getSymbol().getSource() == SourceType.DEFAULT) continue;
            if (nsFilter != null) {
                var parent = f.getParentNamespace();
                if (!nsFilter.equals(parent.getName(false)) && !nsFilter.equals(parent.getName(true))) continue;
            }
            var oldName = f.getName();
            var newName = convention.apply(oldName);
            if (!newName.isBlank() && !newName.equals(oldName)) {
                changes.add(new Change(f.getEntryPoint().toString(), oldName, newName, f));
            }
        }

        var statuses = new String[changes.size()];
        java.util.Arrays.fill(statuses, "preview");
        var applied = new int[1];
        if (apply && !changes.isEmpty()) {
            ctx.runOnSwingTx(program, "Apply naming convention", () -> {
                var temp = new String[changes.size()];
                for (int i = 0; i < changes.size(); i++) {
                    try {
                        var name = uniqueTempName(program, changes.get(i).function());
                        changes.get(i).function().setName(name, SourceType.USER_DEFINED);
                        temp[i] = name;
                    } catch (Exception e) {
                        statuses[i] = "failed: " + rootMessage(e);
                        Msg.error(ctx.logOwner(), "Rename (stage 1) failed for " + changes.get(i).address(), e);
                    }
                }
                for (int i = 0; i < changes.size(); i++) {
                    if (temp[i] == null) continue;
                    var c = changes.get(i);
                    try {
                        c.function().setName(c.newName(), SourceType.USER_DEFINED);
                        statuses[i] = "ok";
                        applied[0]++;
                    } catch (Exception e) {
                        statuses[i] = "failed: " + rootMessage(e);
                        Msg.error(ctx.logOwner(), "Rename (stage 2) failed for " + c.address(), e);
                        try {
                            c.function().setName(c.oldName(), SourceType.USER_DEFINED);
                        } catch (Exception revert) {
                            Msg.error(ctx.logOwner(), "Revert failed for " + c.address(), revert);
                        }
                    }
                }
                return true;
            });
        }

        int failed = 0;
        for (var s : statuses) {
            if (s.startsWith("failed")) failed++;
        }
        var sb = new StringBuilder();
        if (apply) {
            sb.append("# applied ").append(applied[0]).append(" of ").append(changes.size()).append(" rename(s)");
            if (failed > 0) sb.append("; ").append(failed).append(" failed");
        } else {
            sb.append("# preview (dry-run, pass apply=1 to commit) ").append(changes.size()).append(" rename(s)");
        }
        sb.append(" to ").append(convention.name().toLowerCase(java.util.Locale.ROOT)).append('\n');
        sb.append("address\told\tnew\tstatus\n");
        int shown = Math.min(changes.size(), MAX_PREVIEW);
        for (int i = 0; i < shown; i++) {
            var c = changes.get(i);
            sb.append(c.address()).append('\t')
                    .append(Responses.cell(c.oldName())).append('\t')
                    .append(Responses.cell(c.newName())).append('\t')
                    .append(Responses.cell(statuses[i])).append('\n');
        }
        if (changes.size() > shown) {
            sb.append("# ").append(changes.size() - shown).append(" more not shown\n");
        }
        return sb.toString();
    }

    private static String uniqueTempName(Program program, Function f) {
        var base = "__mcp_rename_tmp_" + f.getEntryPoint();
        var ns = f.getParentNamespace();
        var st = program.getSymbolTable();
        var name = base;
        int suffix = 0;
        while (!st.getSymbols(name, ns).isEmpty()) {
            name = base + "_" + suffix++;
        }
        return name;
    }

    private static String rootMessage(Throwable e) {
        var msg = e.getMessage();
        return msg == null || msg.isBlank() ? e.getClass().getSimpleName() : msg;
    }

    public String setVariables(String addr, String newName, String prototype, String variablesJson) {
        if (addr == null || addr.isBlank()) throw new IllegalArgumentException("function_address is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var a = Addresses.parse(program, addr);
        if (a == null) throw new IllegalArgumentException("invalid address: " + addr);
        if (Addresses.functionAtOrContaining(program, a) == null) {
            throw new IllegalArgumentException("No function at " + addr);
        }
        var vars = variablesJson == null || variablesJson.isBlank()
                ? java.util.List.<Map<String, String>>of() : Json.parseObjectArray(variablesJson);
        var hasName = newName != null && !newName.isBlank();
        var hasProto = prototype != null && !prototype.isBlank();
        if (!hasName && !hasProto && vars.isEmpty()) {
            throw new IllegalArgumentException("provide at least one of new_name, prototype, variables");
        }
        var report = new StringBuilder("# field\tresult\tdetail\n");
        var failed = new boolean[1];
        var committed = ctx.runOnSwingTx(program, "Set variables", () -> {
            var func = Addresses.functionAtOrContaining(program, a);
            var dtm = program.getDataTypeManager();
            if (hasName) {
                try {
                    func.setName(newName, SourceType.USER_DEFINED);
                    report.append("name\tok\t").append(Responses.cell(newName)).append('\n');
                } catch (Exception e) {
                    report.append("name\tfail\t").append(Responses.cell(e.getMessage())).append('\n');
                    failed[0] = true;
                }
            }
            if (hasProto) {
                try {
                    var parser = new FunctionSignatureParser(dtm, ctx.service(DataTypeManagerService.class));
                    var pc = extractCc(prototype);
                    var sig = parser.parse(null, pc.proto());
                    if (sig == null) throw new IllegalStateException("prototype parse failed");
                    var cmd = new ApplyFunctionSignatureCmd(func.getEntryPoint(), sig, SourceType.USER_DEFINED);
                    if (!cmd.applyTo(program, new ConsoleTaskMonitor())) throw new IllegalStateException(cmd.getStatusMsg());
                    if (pc.cc() != null) {
                        try {
                            func.setCallingConvention(pc.cc());
                        } catch (Exception ignored) {
                        }
                    }
                    report.append("prototype\tok\t\n");
                } catch (Exception e) {
                    report.append("prototype\tfail\t").append(Responses.cell(e.getMessage())).append('\n');
                    failed[0] = true;
                }
            }
            if (!vars.isEmpty()) {
                var decomp = new DecompInterface();
                try {
                    decomp.openProgram(program);
                    decomp.setSimplificationStyle("decompile");
                    var high = decompileHigh(decomp, func);
                    if (high == null) {
                        report.append("variables\tfail\tdecompilation failed\n");
                        failed[0] = true;
                    } else {
                        var index = new java.util.HashMap<String, HighSymbol>();
                        for (var it = high.getLocalSymbolMap().getSymbols(); it.hasNext(); ) {
                            var s = it.next();
                            index.put(s.getName(), s);
                        }
                        for (var v : vars) {
                            if (!applyVariableEdit(dtm, high, index, v, report)) failed[0] = true;
                        }
                    }
                } finally {
                    decomp.dispose();
                }
            }
            return !failed[0];
        });
        if (!committed) {
            throw new IllegalStateException("rolled back, no changes applied:\n" + report);
        }
        return report.toString();
    }

    private boolean applyVariableEdit(ghidra.program.model.data.DataTypeManager dtm, HighFunction high,
                                      Map<String, HighSymbol> index, Map<String, String> v, StringBuilder report) {
        var varName = v.get("variable_name");
        try {
            if (varName == null || varName.isBlank()) throw new IllegalArgumentException("variable_name is required");
            var symbol = index.get(varName);
            if (symbol == null) throw new IllegalArgumentException("variable not found: " + varName);
            var newType = v.get("new_type");
            ghidra.program.model.data.DataType dt = null;
            if (newType != null && !newType.isBlank()) {
                dt = DataTypes.resolveDataType(dtm, newType);
                if (dt == null) throw new IllegalArgumentException("unknown type: " + newType);
            }
            var rename = v.get("new_name");
            var finalName = rename == null || rename.isBlank() ? varName : rename;
            if (requiresFullCommit(symbol, high)) {
                HighFunctionDBUtil.commitParamsToDatabase(high, false,
                        ReturnCommitOption.NO_COMMIT, high.getFunction().getSignatureSource());
            }
            HighFunctionDBUtil.updateDBVariable(symbol, finalName, dt, SourceType.USER_DEFINED);
            index.remove(varName);
            index.put(finalName, symbol);
            report.append("var:").append(Responses.cell(varName)).append("\tok\t")
                    .append(Responses.cell(finalName)).append('\n');
            return true;
        } catch (Exception e) {
            report.append("var:").append(Responses.cell(varName)).append("\tfail\t")
                    .append(Responses.cell(e.getMessage())).append('\n');
            return false;
        }
    }

    public String batchSetPrototype(String itemsJson) {
        var items = parseBatch(itemsJson);
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var report = new StringBuilder("# result\taddress\tdetail\n");
        var okCount = new int[1];
        ctx.runOnSwingTx(program, "Batch set prototype", () -> {
            var dtm = program.getDataTypeManager();
            var parser = new FunctionSignatureParser(dtm, ctx.service(DataTypeManagerService.class));
            var monitor = new ConsoleTaskMonitor();
            for (var it : items) {
                var addr = it.get("function_address");
                try {
                    var proto = it.get("prototype");
                    if (proto == null || proto.isBlank()) throw new IllegalArgumentException("prototype is required");
                    var a = Addresses.parse(program, addr);
                    if (a == null) throw new IllegalArgumentException("invalid address");
                    var func = Addresses.functionAtOrContaining(program, a);
                    if (func == null) throw new IllegalArgumentException("no function at address");
                    var pc = extractCc(proto);
                    var sig = parser.parse(null, pc.proto());
                    if (sig == null) throw new IllegalStateException("prototype parse failed");
                    var cmd = new ApplyFunctionSignatureCmd(func.getEntryPoint(), sig, SourceType.USER_DEFINED);
                    if (!cmd.applyTo(program, monitor)) throw new IllegalStateException(cmd.getStatusMsg());
                    if (pc.cc() != null) {
                        try {
                            func.setCallingConvention(pc.cc());
                        } catch (Exception ignored) {
                        }
                    }
                    okCount[0]++;
                    report.append("ok\t").append(Responses.cell(addr)).append("\t\n");
                } catch (Exception e) {
                    report.append("fail\t").append(Responses.cell(addr)).append('\t')
                            .append(Responses.cell(e.getMessage())).append('\n');
                }
            }
            return true;
        });
        return "set " + okCount[0] + "/" + items.size() + "\n" + report;
    }

    public String batchSetVariableType(String itemsJson) {
        var items = parseBatch(itemsJson);
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var report = new StringBuilder("# result\taddress\tdetail\n");
        var okCount = new int[1];
        ctx.runOnSwingTx(program, "Batch set variable type", () -> {
            var decomp = new DecompInterface();
            try {
                decomp.openProgram(program);
                decomp.setSimplificationStyle("decompile");
                var dtm = program.getDataTypeManager();
                for (var it : items) {
                    var addr = it.get("function_address");
                    try {
                        var varName = it.get("variable_name");
                        var newType = it.get("new_type");
                        if (varName == null || varName.isBlank() || newType == null || newType.isBlank()) {
                            throw new IllegalArgumentException("variable_name and new_type are required");
                        }
                        var a = Addresses.parse(program, addr);
                        if (a == null) throw new IllegalArgumentException("invalid address");
                        var func = Addresses.functionAtOrContaining(program, a);
                        if (func == null) throw new IllegalArgumentException("no function at address");
                        var high = decompileHigh(decomp, func);
                        if (high == null) throw new IllegalStateException("decompilation failed");
                        var symbol = findHighSymbol(high, varName);
                        if (symbol == null) throw new IllegalArgumentException("variable not found: " + varName);
                        var dt = DataTypes.resolveDataType(dtm, newType);
                        if (dt == null) throw new IllegalArgumentException("unknown type: " + newType);
                        if (requiresFullCommit(symbol, high)) {
                            HighFunctionDBUtil.commitParamsToDatabase(high, false,
                                    ReturnCommitOption.NO_COMMIT, func.getSignatureSource());
                        }
                        HighFunctionDBUtil.updateDBVariable(symbol, symbol.getName(), dt, SourceType.USER_DEFINED);
                        okCount[0]++;
                        report.append("ok\t").append(Responses.cell(addr)).append('\t')
                                .append(Responses.cell(varName)).append('\n');
                    } catch (Exception e) {
                        report.append("fail\t").append(Responses.cell(addr)).append('\t')
                                .append(Responses.cell(e.getMessage())).append('\n');
                    }
                }
                return true;
            } finally {
                decomp.dispose();
            }
        });
        return "set " + okCount[0] + "/" + items.size() + "\n" + report;
    }

    private static HighFunction decompileHigh(DecompInterface decomp, ghidra.program.model.listing.Function func) {
        var results = decomp.decompileFunction(func, DecompileHandlers.DECOMPILE_TIMEOUT_SEC, new ConsoleTaskMonitor());
        return results != null && results.decompileCompleted() ? results.getHighFunction() : null;
    }

    private java.util.List<Map<String, String>> parseBatch(String itemsJson) {
        if (itemsJson == null || itemsJson.isBlank()) {
            throw new IllegalArgumentException("items JSON array is required");
        }
        try {
            var items = Json.parseObjectArray(itemsJson);
            if (items.isEmpty()) throw new IllegalArgumentException("items is empty");
            return items;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid items JSON: " + e.getMessage());
        }
    }

    public String batchRename(String itemsJson) {
        var items = parseBatch(itemsJson);
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var report = new StringBuilder("# result\taddress\tdetail\n");
        var okCount = new int[1];
        ctx.runOnSwingTx(program, "Batch rename", () -> {
            for (var it : items) {
                var addr = it.get("address");
                try {
                    var newName = it.get("new_name");
                    if (newName == null || newName.isBlank()) {
                        throw new IllegalArgumentException("new_name is required");
                    }
                    var a = addr == null ? null : program.getAddressFactory().getAddress(addr);
                    if (a == null) throw new IllegalArgumentException("invalid address");
                    var func = program.getFunctionManager().getFunctionAt(a);
                    String detail;
                    if (func != null) {
                        func.setName(newName, SourceType.USER_DEFINED);
                        detail = newName + " (function)";
                    } else {
                        var sym = program.getSymbolTable().getPrimarySymbol(a);
                        if (sym != null) {
                            sym.setName(newName, SourceType.USER_DEFINED);
                            detail = newName + " (symbol)";
                        } else {
                            program.getSymbolTable().createLabel(a, newName, SourceType.USER_DEFINED);
                            detail = newName + " (NEW label — no function/symbol was at this address)";
                        }
                    }
                    okCount[0]++;
                    report.append("ok\t").append(addr).append('\t').append(detail).append('\n');
                } catch (Exception e) {
                    report.append("fail\t").append(addr).append('\t')
                            .append(e.getMessage()).append('\n');
                }
            }
            return true;
        });
        return "renamed " + okCount[0] + "/" + items.size() + "\n" + report;
    }

    public String batchSetComment(String itemsJson) {
        var items = parseBatch(itemsJson);
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var report = new StringBuilder("# result\taddress\tdetail\n");
        var okCount = new int[1];
        ctx.runOnSwingTx(program, "Batch set comment", () -> {
            for (var it : items) {
                var addr = it.get("address");
                try {
                    var comment = it.get("comment");
                    if (comment == null) throw new IllegalArgumentException("comment is required");
                    var a = addr == null ? null : program.getAddressFactory().getAddress(addr);
                    if (a == null) throw new IllegalArgumentException("invalid address");
                    int type = "pre".equals(it.get("kind"))
                            ? CodeUnit.PRE_COMMENT : CodeUnit.EOL_COMMENT;
                    program.getListing().setComment(a, type, comment);
                    okCount[0]++;
                    report.append("ok\t").append(addr).append("\t\n");
                } catch (Exception e) {
                    report.append("fail\t").append(addr).append('\t')
                            .append(e.getMessage()).append('\n');
                }
            }
            return true;
        });
        return "commented " + okCount[0] + "/" + items.size() + "\n" + report;
    }

    private static String require(boolean ok, String success, String failure) {
        if (!ok) throw new IllegalStateException(failure);
        return success;
    }

    public boolean createLabel(String addr, String name) {
        if (addr == null || name == null || name.isBlank()) return false;
        var program = ctx.currentProgram();
        if (program == null) return false;
        return ctx.runOnSwingTx(program, "Create label", () -> {
            try {
                var a = program.getAddressFactory().getAddress(addr);
                if (a == null) return false;
                program.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
                return true;
            } catch (Exception e) {
                Msg.error(ctx.logOwner(), "createLabel failed", e);
                return false;
            }
        });
    }

    public boolean renameFunction(String oldName, String newName) {
        if (oldName == null || newName == null) return false;
        var program = ctx.currentProgram();
        if (program == null) return false;
        return ctx.runOnSwingTx(program, "Rename function via HTTP", () -> {
            var func = Programs.findFunctionByName(program, oldName);
            if (func == null) return false;
            try {
                func.setName(newName, SourceType.USER_DEFINED);
                return true;
            } catch (Exception e) {
                Msg.error(ctx.logOwner(), "Error renaming function", e);
                return false;
            }
        });
    }

    public String renameDataAt(String addrStr, String newName) {
        if (addrStr == null || addrStr.isBlank() || newName == null || newName.isBlank()) {
            throw new IllegalArgumentException("address and newName are required");
        }
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var result = new String[]{"Rename failed"};
        var ok = ctx.runOnSwingTx(program, "Rename data", () -> {
            try {
                var addr = program.getAddressFactory().getAddress(addrStr);
                if (addr == null) {
                    throw new IllegalArgumentException("Invalid address: " + addrStr);
                }
                var table = program.getSymbolTable();
                var sym = table.getPrimarySymbol(addr);
                if (sym != null) {
                    sym.setName(newName, SourceType.USER_DEFINED);
                } else {
                    table.createLabel(addr, newName, SourceType.USER_DEFINED);
                }
                result[0] = "Renamed " + addrStr + " to " + newName;
                return true;
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                Msg.error(ctx.logOwner(), "Rename data error", e);
                throw new IllegalStateException("Rename failed: " + e.getMessage(), e);
            }
        });
        return require(ok, result[0], "Rename failed");
    }

    public String renameVariable(String functionName, String oldVar, String newVar) {
        if (functionName == null || oldVar == null || newVar == null) throw new IllegalArgumentException("Missing parameters");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var func = Programs.findFunctionByName(program, functionName);
        if (func == null) throw new IllegalArgumentException("Function not found");

        var decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            var results = decomp.decompileFunction(func, DecompileHandlers.DECOMPILE_TIMEOUT_SEC, new ConsoleTaskMonitor());
            if (results == null || !results.decompileCompleted()) throw new IllegalStateException("Decompilation failed");
            var high = results.getHighFunction();
            if (high == null) throw new IllegalStateException("Decompilation failed (no high function)");
            var map = high.getLocalSymbolMap();
            if (map == null) throw new IllegalStateException("Decompilation failed (no local symbol map)");

            HighSymbol target = null;
            for (var it = map.getSymbols(); it.hasNext(); ) {
                var s = it.next();
                if (s.getName().equals(newVar)) throw new IllegalArgumentException("variable " + newVar + " already exists");
                if (s.getName().equals(oldVar)) target = s;
            }
            if (target == null) return "Variable not found";

            var needsCommit = requiresFullCommit(target, high);
            var symbol = target;
            var ok = ctx.runOnSwingTx(program, "Rename variable", () -> {
                try {
                    if (needsCommit) {
                        HighFunctionDBUtil.commitParamsToDatabase(high, false,
                                ReturnCommitOption.NO_COMMIT, func.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(symbol, newVar, null, SourceType.USER_DEFINED);
                    return true;
                } catch (Exception e) {
                    Msg.error(ctx.logOwner(), "Failed to rename variable", e);
                    return false;
                }
            });
            if (!ok) throw new IllegalStateException("Failed to rename variable");
            return "Variable renamed";
        } finally {
            decomp.dispose();
        }
    }

    private static boolean requiresFullCommit(HighSymbol sym, HighFunction high) {
        if (sym != null && !sym.isParameter()) return false;
        var func = high.getFunction();
        Parameter[] params = func.getParameters();
        LocalSymbolMap map = high.getLocalSymbolMap();
        if (map.getNumParams() != params.length) return true;
        for (int i = 0; i < params.length; i++) {
            var hp = map.getParamSymbol(i);
            if (hp.getCategoryIndex() != i) return true;
            VariableStorage storage = hp.getStorage();
            if (storage.compareTo(params[i].getVariableStorage()) != 0) return true;
        }
        return false;
    }

    public boolean renameFunctionAt(String addr, String newName) {
        if (addr == null || addr.isBlank() || newName == null || newName.isBlank()) return false;
        var program = ctx.currentProgram();
        if (program == null) return false;
        return ctx.runOnSwingTx(program, "Rename function by address", () -> {
            try {
                var a = program.getAddressFactory().getAddress(addr);
                var func = Addresses.functionAtOrContaining(program, a);
                if (func == null) {
                    Msg.error(ctx.logOwner(), "No function at: " + addr);
                    return false;
                }
                func.setName(newName, SourceType.USER_DEFINED);
                return true;
            } catch (Exception e) {
                Msg.error(ctx.logOwner(), "Error renaming function by address", e);
                return false;
            }
        });
    }

    public boolean setComment(String addr, String comment, int type, String txName) {
        if (addr == null || addr.isBlank() || comment == null) return false;
        var program = ctx.currentProgram();
        if (program == null) return false;
        return ctx.runOnSwingTx(program, txName, () -> {
            try {
                var a = program.getAddressFactory().getAddress(addr);
                program.getListing().setComment(a, type, comment);
                return true;
            } catch (Exception e) {
                Msg.error(ctx.logOwner(), "Error in " + txName, e);
                return false;
            }
        });
    }

    public PrototypeResult setFunctionPrototype(String addr, String prototype) {
        if (addr == null || addr.isBlank()) return new PrototypeResult.Failed("Function address is required");
        if (prototype == null || prototype.isBlank()) return new PrototypeResult.Failed("Function prototype is required");
        var program = ctx.currentProgram();
        if (program == null) return new PrototypeResult.Failed("No program loaded");

        var errorBuf = new StringBuilder();
        var ok = ctx.runOnSwing(() -> {
            try {
                var a = program.getAddressFactory().getAddress(addr);
                var func = Addresses.functionAtOrContaining(program, a);
                if (func == null) {
                    errorBuf.append("Could not find function at address: ").append(addr);
                    return false;
                }
                addPrototypeComment(program, func, prototype);
                return applyPrototype(program, a, prototype, errorBuf);
            } catch (Exception e) {
                errorBuf.append("Error setting function prototype: ").append(e.getMessage());
                Msg.error(ctx.logOwner(), "setFunctionPrototype failed", e);
                return false;
            }
        });
        return ok ? new PrototypeResult.Ok(errorBuf.toString())
                  : new PrototypeResult.Failed(errorBuf.toString());
    }

    private void addPrototypeComment(Program program, ghidra.program.model.listing.Function func, String prototype) {
        int tx = program.startTransaction("Add prototype comment");
        boolean ok = false;
        try {
            program.getListing().setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT,
                    "Setting prototype: " + prototype);
            ok = true;
        } finally {
            program.endTransaction(tx, ok);
        }
    }

    private static final java.util.regex.Pattern CC_KEYWORD = java.util.regex.Pattern.compile(
            "\\b(__thiscall|__fastcall|__cdecl|__stdcall|__vectorcall)\\b");

    private record ProtoCc(String proto, String cc) {}

    static ProtoCc extractCc(String prototype) {
        var m = CC_KEYWORD.matcher(prototype);
        if (!m.find()) return new ProtoCc(prototype, null);
        var cc = m.group(1);
        var cleaned = CC_KEYWORD.matcher(prototype).replaceAll(" ").replaceAll("\\s+", " ").trim();
        return new ProtoCc(cleaned, cc);
    }

    private boolean applyPrototype(Program program, Address addr, String prototype, StringBuilder errorBuf) {
        int tx = program.startTransaction("Set function prototype");
        boolean ok = false;
        try {
            var dtm = program.getDataTypeManager();
            var dtms = ctx.service(DataTypeManagerService.class);
            var pc = extractCc(prototype);
            var parser = new FunctionSignatureParser(dtm, dtms);
            FunctionDefinitionDataType sig = parser.parse(null, pc.proto());
            if (sig == null) {
                errorBuf.append("Failed to parse function prototype");
                return false;
            }
            var cmd = new ApplyFunctionSignatureCmd(addr, sig, SourceType.USER_DEFINED);
            ok = cmd.applyTo(program, new ConsoleTaskMonitor());
            if (!ok) {
                errorBuf.append("Command failed: ").append(cmd.getStatusMsg());
                return false;
            }
            if (pc.cc() != null) {
                var func = Addresses.functionAtOrContaining(program, addr);
                try {
                    if (func != null) func.setCallingConvention(pc.cc());
                } catch (Exception e) {
                    errorBuf.append("prototype set; calling convention '").append(pc.cc())
                            .append("' not applied: ").append(e.getMessage());
                }
            }
            return true;
        } catch (Exception e) {
            errorBuf.append("Error applying signature: ").append(e.getMessage());
            Msg.error(ctx.logOwner(), "applyPrototype failed", e);
            return false;
        } finally {
            program.endTransaction(tx, ok);
        }
    }

    public String setLocalVariableType(String addr, String variable, String newType) {
        if (addr == null || addr.isBlank() || variable == null || variable.isBlank()
                || newType == null || newType.isBlank()) {
            throw new IllegalArgumentException("function_address, variable_name, and new_type are required");
        }
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        return Swing.runNow(() -> {
            try {
                var a = program.getAddressFactory().getAddress(addr);
                if (a == null) throw new IllegalArgumentException("invalid address: " + addr);
                var func = Addresses.functionAtOrContaining(program, a);
                if (func == null) throw new IllegalArgumentException("No function at " + addr);
                var dataType = DataTypes.resolveDataType(program.getDataTypeManager(), newType);
                if (dataType == null) throw new IllegalArgumentException("Unknown type: " + newType);
                var decomp = new DecompInterface();
                try {
                    decomp.openProgram(program);
                    decomp.setSimplificationStyle("decompile");
                    var results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());
                    if (!results.decompileCompleted()) throw new IllegalStateException("Decompilation failed for " + func.getName());
                    var high = results.getHighFunction();
                    if (high == null) throw new IllegalStateException("No high function for " + func.getName());
                    var symbol = findHighSymbol(high, variable);
                    if (symbol == null) {
                        return "Variable '" + variable + "' not found. Use the exact decompiler name; "
                                + "rename it first if it is an auto temp.";
                    }
                    int tx = program.startTransaction("Set variable type");
                    boolean ok = false;
                    try {
                        HighFunctionDBUtil.updateDBVariable(symbol, symbol.getName(),
                                dataType, SourceType.USER_DEFINED);
                        ok = true;
                        return "Variable type set successfully";
                    } finally {
                        program.endTransaction(tx, ok);
                    }
                } finally {
                    decomp.dispose();
                }
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                Msg.error(ctx.logOwner(), "setLocalVariableType failed", e);
                throw new IllegalStateException("Failed: " + e.getClass().getSimpleName()
                        + (e.getMessage() != null ? " - " + e.getMessage() : ""), e);
            }
        });
    }

    private static HighSymbol findHighSymbol(HighFunction high, String name) {
        for (var it = high.getLocalSymbolMap().getSymbols(); it.hasNext(); ) {
            var s = it.next();
            if (s.getName().equals(name)) return s;
        }
        return null;
    }

    public String importCHeader(String header, String category) {
        if (header == null || header.isBlank()) throw new IllegalArgumentException("Header text is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var result = new String[1];
        var ok = ctx.runOnSwingTx(program, "Import C header", () -> {
            try {
                var dtm = program.getDataTypeManager();
                var parser = new ghidra.app.util.cparser.C.CParser(dtm);
                parser.parse(new java.io.ByteArrayInputStream(header.getBytes(StandardCharsets.UTF_8)));
                var composites = parser.getComposites();
                var enums = parser.getEnums();
                var types = parser.getTypes();
                CategoryPath cat = (category == null || category.isEmpty())
                        ? CategoryPath.ROOT : new CategoryPath(category);
                int added = 0;
                for (var dt : composites.values()) {
                    var copy = dt.copy(dtm);
                    copy.setCategoryPath(cat);
                    if (dtm.addDataType(copy, DataTypeConflictHandler.REPLACE_HANDLER) != null) added++;
                }
                for (var dt : enums.values()) {
                    var copy = dt.copy(dtm);
                    copy.setCategoryPath(cat);
                    if (dtm.addDataType(copy, DataTypeConflictHandler.REPLACE_HANDLER) != null) added++;
                }
                for (var dt : types.values()) {
                    var copy = dt.copy(dtm);
                    copy.setCategoryPath(cat);
                    if (dtm.addDataType(copy, DataTypeConflictHandler.REPLACE_HANDLER) != null) added++;
                }
                var msgs = parser.getParseMessages();
                result[0] = "Added " + added + " types"
                        + (msgs != null && !msgs.isEmpty() ? "\nparse_messages:\n" + msgs : "");
                return true;
            } catch (Exception e) {
                result[0] = "Parse error: " + e.getClass().getSimpleName() + ": " + e.getMessage();
                return false;
            }
        });
        if (!ok) {
            throw new IllegalStateException(result[0] != null ? result[0] : "Import failed");
        }
        return result[0];
    }

    public String createStruct(String name, String fieldsJson) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Name is required");
        if (fieldsJson == null || fieldsJson.isBlank()) throw new IllegalArgumentException("Fields JSON is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        java.util.List<Map<String, String>> fields;
        try {
            fields = Json.parseObjectArray(fieldsJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid fields JSON: " + e.getMessage());
        }
        var out = new String[1];
        var ok = ctx.runOnSwingTx(program, "Create struct", () -> {
            try {
                var dtm = program.getDataTypeManager();
                var s = new StructureDataType(name, 0, dtm);
                for (var f : fields) {
                    var fname = f.get("name");
                    var ftype = f.get("type");
                    var offStr = f.get("offset");
                    if (fname == null || ftype == null) {
                        out[0] = "Each field needs name,type";
                        return false;
                    }
                    var dt = DataTypes.resolveDataType(dtm, ftype);
                    if (dt == null) { out[0] = "Unknown type: " + ftype; return false; }
                    int len = dt.getLength() > 0 ? dt.getLength() : 1;
                    if (offStr != null && !offStr.isEmpty()) {
                        int off = Integer.parseInt(offStr);
                        s.insertAtOffset(off, dt, len, fname, null);
                    } else {
                        s.add(dt, len, fname, null);
                    }
                }
                dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);
                out[0] = "Created struct " + name + " (size=" + s.getLength() + ")";
                return true;
            } catch (Exception e) {
                out[0] = "Error: " + e.getClass().getSimpleName() + ": " + e.getMessage();
                return false;
            }
        });
        if (!ok) throw new IllegalStateException(out[0] != null ? out[0] : "Failed");
        return out[0];
    }

    public String createUnion(String name, String fieldsJson) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Name is required");
        if (fieldsJson == null || fieldsJson.isBlank()) throw new IllegalArgumentException("Fields JSON is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        java.util.List<Map<String, String>> fields;
        try {
            fields = Json.parseObjectArray(fieldsJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid fields JSON: " + e.getMessage());
        }
        var out = new String[1];
        var ok = ctx.runOnSwingTx(program, "Create union", () -> {
            try {
                var dtm = program.getDataTypeManager();
                var u = new UnionDataType(name);
                for (var f : fields) {
                    var fname = f.get("name");
                    var ftype = f.get("type");
                    if (fname == null || ftype == null) {
                        out[0] = "Each field needs name,type";
                        return false;
                    }
                    var dt = DataTypes.resolveDataType(dtm, ftype);
                    if (dt == null) { out[0] = "Unknown type: " + ftype; return false; }
                    int len = dt.getLength() > 0 ? dt.getLength() : 1;
                    u.add(dt, len, fname, null);
                }
                dtm.addDataType(u, DataTypeConflictHandler.REPLACE_HANDLER);
                out[0] = "Created union " + name + " (size=" + u.getLength() + ")";
                return true;
            } catch (Exception e) {
                out[0] = "Error: " + e.getClass().getSimpleName() + ": " + e.getMessage();
                return false;
            }
        });
        if (!ok) throw new IllegalStateException(out[0] != null ? out[0] : "Failed");
        return out[0];
    }

    public String createEnum(String name, int size, String valuesJson) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Name is required");
        if (size != 1 && size != 2 && size != 4 && size != 8) throw new IllegalArgumentException("Size must be 1/2/4/8");
        if (valuesJson == null || valuesJson.isBlank()) throw new IllegalArgumentException("Values JSON is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        java.util.List<Map<String, String>> values;
        try {
            values = Json.parseObjectArray(valuesJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid values JSON: " + e.getMessage());
        }
        var out = new String[1];
        var ok = ctx.runOnSwingTx(program, "Create enum", () -> {
            try {
                var dtm = program.getDataTypeManager();
                var e = new EnumDataType(name, size);
                for (var v : values) {
                    var vname = v.get("name");
                    var vval = v.get("value");
                    if (vname == null || vval == null) {
                        out[0] = "Each entry needs name,value";
                        return false;
                    }
                    e.add(vname, parseEnumValue(vval.trim()));
                }
                dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER);
                out[0] = "Created enum " + name + " (" + values.size() + " members)";
                return true;
            } catch (Exception ex) {
                out[0] = "Error: " + ex.getClass().getSimpleName() + ": " + ex.getMessage();
                return false;
            }
        });
        if (!ok) throw new IllegalStateException(out[0] != null ? out[0] : "Failed");
        return out[0];
    }

    private static long parseEnumValue(String v) {
        if (v.startsWith("0x") || v.startsWith("0X")) {
            return Long.parseUnsignedLong(v.substring(2), 16);
        }
        return v.startsWith("-") ? Long.parseLong(v) : Long.parseUnsignedLong(v);
    }
}
