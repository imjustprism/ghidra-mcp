package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.app.services.CodeViewerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.analysis.DecompileMinimal;
import io.github.imjustprism.ghidra.mcp.analysis.FieldWrites;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.DecompileCache;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Programs;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.Map;
import java.util.function.Supplier;

public final class FunctionHandlers {

    private final PluginContext ctx;

    public FunctionHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    public void register(RouteTable routes) {
        routes.getQuery("/list_functions", this::listFunctions);
        routes.getQuery("/get_current_address", q -> getCurrentAddress());
        routes.getQuery("/get_current_function", q -> describeCurrentFunction());
        routes.getQuery("/get_function_by_address", q -> describeFunctionAt(q.get("address")));
        routes.getQuery("/searchFunctions", q -> searchFunctions(q.get("query"), Page.from(q), q));
        routes.getQuery("/xrefs", q -> switch (q.getOrDefault("direction", "both")) {
            case "to" -> xrefsTo(q.get("target"), Page.from(q), q);
            case "from" -> xrefsFrom(q.get("target"), Page.from(q), q);
            default -> functionXrefs(q.get("target"), Page.from(q), q);
        });
        routes.getQuery("/list_callers", q -> listCallers(q.get("address"), Page.from(q), q));
        routes.getQuery("/list_callees", q -> listCallees(q.get("address"), Page.from(q), q));
        routes.getQuery("/basic_blocks", q -> listBasicBlocks(q.get("address"), q));
        routes.getQuery("/function_string_refs", q -> functionStringRefs(q.get("address"), Page.from(q), q));
        routes.getQuery("/function_stack_frame", q -> functionStackFrame(q.get("address"), q));
        routes.getQuery("/function_summary", q -> functionSummary(q.get("address"), q));
        routes.getQuery("/function_field_writes", q -> functionFieldWrites(q.get("address"), q));
    }

    public String functionSummary(String addr, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("No function at " + addr);
            var p = Page.from(q);
            var sb = new StringBuilder(4096);
            sb.append("=== function ===\n").append(formatFunction(func));
            sb.append("=== decompile ===\n")
              .append(section(() -> DecompileMinimal.minimize(DecompileCache.decompile(program, func)))).append('\n');
            sb.append("=== callers ===\n").append(section(() -> callersTable(func, p, q))).append('\n');
            sb.append("=== callees ===\n").append(section(() -> calleesTable(func, p, q))).append('\n');
            sb.append("=== strings ===\n").append(section(() -> stringRefsTable(program, func, p, q)));
            return sb.toString();
        });
    }

    public String functionFieldWrites(String addr, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("No function at " + addr);
            var p = Page.from(q);
            var writes = FieldWrites.extract(DecompileCache.decompile(program, func));
            var t = Responses.table(p, q, new String[]{"kind", "offset", "target", "value"});
            var w = new Responses.Window(p);
            for (var r : writes) {
                if (!w.take()) continue;
                t.row(r.kind(), r.offset(), r.lhs(), r.rhs());
            }
            return "=== field_writes ===\n" + t.total(w.total()).build()
                    + "=== strings ===\n" + stringRefsTable(program, func, p, q);
        });
    }

    private static String section(Supplier<String> body) {
        try {
            return body.get();
        } catch (Exception e) {
            return "(unavailable: " + e.getMessage() + ")\n";
        }
    }

    public String listFunctions(Map<String, String> q) {
        var p = Page.from(q);
        var withAddr = q.get("with_address");
        if ("0".equals(withAddr) || "false".equalsIgnoreCase(withAddr)) {
            return ctx.withProgram(program ->
                    Responses.pageStream(q, p, "fn", Programs.functions(program).map(Function::getName)));
        }
        return ctx.withProgram(program -> {
            boolean includeAuto = "1".equals(q.get("include_auto"));
            var t = Responses.table(p, q, new String[]{"fn", "addr"});
            var w = new Responses.Window(p);
            for (var f : program.getFunctionManager().getFunctions(true)) {
                var name = f.getName();
                if (!includeAuto && Responses.isAutoName(name)) continue;
                if (!w.take()) continue;
                t.row(name, Responses.addr(f.getEntryPoint()));
            }
            return t.total(w.total()).build();
        });
    }

    public String searchFunctions(String term, Page p, Map<String, String> q) {
        if (term == null || term.isBlank()) throw new IllegalArgumentException("Search term is required");
        return ctx.withProgram(program -> {
            var lower = term.toLowerCase();
            var t = Responses.table(p, q, new String[]{"fn", "addr"});
            var w = new Responses.Window(p);
            for (var f : program.getFunctionManager().getFunctions(true)) {
                var name = f.getName();
                if (!name.toLowerCase().contains(lower)) continue;
                if (!w.take()) continue;
                t.row(name, Responses.addr(f.getEntryPoint()));
            }
            return t.total(w.total()).build();
        });
    }

    public String getCurrentAddress() {
        var svc = ctx.service(CodeViewerService.class);
        if (svc == null) throw new IllegalStateException("Code viewer service not available");
        var loc = svc.getCurrentLocation();
        return loc != null ? Responses.addr(loc.getAddress()) : "No current location";
    }

    public String describeCurrentFunction() {
        var svc = ctx.service(CodeViewerService.class);
        if (svc == null) throw new IllegalStateException("Code viewer service not available");
        var loc = svc.getCurrentLocation();
        if (loc == null) throw new IllegalArgumentException("No current location");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var func = program.getFunctionManager().getFunctionContaining(loc.getAddress());
        return func == null
                ? "No function at current location: " + loc.getAddress()
                : formatFunction(func);
    }

    public String describeFunctionAt(String addr) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = program.getFunctionManager().getFunctionAt(a);
            if (func == null) throw new IllegalArgumentException("No function at " + addr);
            return formatFunction(func);
        });
    }

    public static String formatFunction(Function f) {
        var body = f.getBody();
        var sb = new StringBuilder(256);
        sb.append("# format=tsv; addr=hex; cols=k,v\n");
        sb.append("fn\t").append(f.getName()).append('\n');
        sb.append("entry\t").append(Responses.addr(f.getEntryPoint())).append('\n');
        sb.append("sig\t").append(Responses.cell(f.getSignature().toString())).append('\n');
        sb.append("body\t").append(Responses.addr(body.getMinAddress()))
          .append('-').append(Responses.addr(body.getMaxAddress())).append('\n');
        return sb.toString();
    }

    public String xrefsTo(String addr, Page p, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var fm = program.getFunctionManager();
            var t = Responses.table(p, q, new String[]{"from", "fn", "type"});
            var w = new Responses.Window(p);
            var it = program.getReferenceManager().getReferencesTo(a);
            while (it.hasNext()) {
                var ref = it.next();
                if (!w.take()) continue;
                var from = ref.getFromAddress();
                var func = fm.getFunctionContaining(from);
                t.row(Responses.addr(from), func != null ? func.getName() : "",
                      ref.getReferenceType().getName());
            }
            return t.total(w.total()).build();
        });
    }

    public String xrefsFrom(String addr, Page p, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var t = Responses.table(p, q, new String[]{"to", "target", "type"});
            var w = new Responses.Window(p);
            for (var ref : program.getReferenceManager().getReferencesFrom(a)) {
                if (!w.take()) continue;
                var to = ref.getToAddress();
                var func = program.getFunctionManager().getFunctionAt(to);
                String target;
                if (func != null) target = func.getName();
                else {
                    var data = program.getListing().getDataAt(to);
                    target = data == null ? "" :
                            (data.getLabel() != null ? data.getLabel() : data.getPathName());
                }
                t.row(Responses.addr(to), target, ref.getReferenceType().getName());
            }
            return t.total(w.total()).build();
        });
    }

    public String functionXrefs(String name, Page p, Map<String, String> q) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Function name is required");
        return ctx.withProgram(program -> {
            var fm = program.getFunctionManager();
            var rm = program.getReferenceManager();
            var t = Responses.table(p, q, new String[]{"from", "fn", "type"});
            var w = new Responses.Window(p);
            var seen = new java.util.HashSet<Address>();
            for (var func : fm.getFunctions(true)) {
                if (func.getName().equals(name)) collectRefs(program, rm.getReferencesTo(func.getEntryPoint()), seen, t, w);
            }
            for (var s : program.getSymbolTable().getExternalSymbols()) {
                if (!s.getName().equals(name)) continue;
                for (var ref : rm.getReferencesTo(s.getAddress())) {
                    var from = ref.getFromAddress();
                    if (ref.getReferenceType().isData() && from.isMemoryAddress()) {
                        collectRefs(program, rm.getReferencesTo(from), seen, t, w);
                    } else {
                        addRow(program, ref, seen, t, w);
                    }
                }
            }
            return t.total(w.total()).build();
        });
    }

    private static void collectRefs(Program program, ReferenceIterator refs,
                                    java.util.Set<Address> seen, Responses.Table t, Responses.Window w) {
        while (refs.hasNext()) addRow(program, refs.next(), seen, t, w);
    }

    private static void addRow(Program program, Reference ref, java.util.Set<Address> seen,
                               Responses.Table t, Responses.Window w) {
        var from = ref.getFromAddress();
        if (!seen.add(from) || !w.take()) return;
        var caller = program.getFunctionManager().getFunctionContaining(from);
        t.row(Responses.addr(from), caller != null ? caller.getName() : "", ref.getReferenceType().getName());
    }

    public String listCallers(String addr, Page p, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> callersTable(requireFunction(program, a, addr), p, q));
    }

    private String callersTable(Function func, Page p, Map<String, String> q) {
        var callers = func.getCallingFunctions(new ConsoleTaskMonitor());
        var t = Responses.table(p, q, new String[]{"fn", "addr"});
        var w = new Responses.Window(p);
        for (var f : callers) {
            if (!w.take()) continue;
            t.row(f.getName(), Responses.addr(f.getEntryPoint()));
        }
        var body = t.total(w.total()).build();
        if (w.total() != 0) return body;
        long dataRefs = addressTakenRefs(func);
        if (dataRefs == 0) return body;
        return body + "# 0 direct callers, but the entry address is taken as data " + dataRefs
                + "x — likely reached indirectly (function pointer / vtable / callback)\n";
    }

    private static long addressTakenRefs(Function func) {
        long n = 0;
        for (var ref : func.getProgram().getReferenceManager().getReferencesTo(func.getEntryPoint())) {
            if (ref.getReferenceType().isData()) n++;
        }
        return n;
    }

    public String listCallees(String addr, Page p, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> calleesTable(requireFunction(program, a, addr), p, q));
    }

    private String calleesTable(Function func, Page p, Map<String, String> q) {
        var callees = func.getCalledFunctions(new ConsoleTaskMonitor());
        var t = Responses.table(p, q, new String[]{"fn", "addr"});
        var w = new Responses.Window(p);
        for (var f : callees) {
            if (!w.take()) continue;
            t.row(f.getName(), Responses.addr(f.getEntryPoint()));
        }
        return t.total(w.total()).build();
    }

    private static Function requireFunction(Program program, ghidra.program.model.address.Address a, String addr) {
        var func = Addresses.functionAtOrContaining(program, a);
        if (func == null) throw new IllegalArgumentException("No function at " + addr);
        return func;
    }

    public String listBasicBlocks(String addr, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("No function at " + addr);
            var model = new BasicBlockModel(program);
            var monitor = new ConsoleTaskMonitor();
            var t = Responses.table(q, new String[]{"start", "end"}, 64);
            int n = 0;
            try {
                var it = model.getCodeBlocksContaining(func.getBody(), monitor);
                while (it.hasNext()) {
                    var block = it.next();
                    t.row(Responses.addr(block.getFirstStartAddress()),
                          Responses.addr(block.getMaxAddress()));
                    n++;
                }
            } catch (Exception e) {
                throw new IllegalStateException("Error enumerating basic blocks: " + e.getMessage(), e);
            }
            return t.total(n).build();
        });
    }

    public String functionStringRefs(String addr, Page p, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> stringRefsTable(program, requireFunction(program, a, addr), p, q));
    }

    private String stringRefsTable(Program program, Function func, Page p, Map<String, String> q) {
        var refs = program.getReferenceManager();
        var listing = program.getListing();
        var t = Responses.table(p, q, new String[]{"from", "to", "value"});
        var w = new Responses.Window(p);
        var iter = func.getBody().getAddresses(true);
        while (iter.hasNext()) {
            var from = iter.next();
            for (var r : refs.getReferencesFrom(from)) {
                var data = listing.getDataAt(r.getToAddress());
                if (data == null || !DataTypes.isStringLike(data)) continue;
                if (!w.take()) continue;
                var s = data.getValue() != null ? data.getValue().toString() : "";
                t.row(Responses.addr(from), Responses.addr(r.getToAddress()),
                      Strings.escapeString(s));
            }
        }
        return t.total(w.total()).build();
    }

    public String functionStackFrame(String addr, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("No function at " + addr);
            var frame = func.getStackFrame();
            if (frame == null) throw new IllegalStateException("No stack frame");
            var t = Responses.table(q, new String[]{"name", "offset", "datatype", "size", "storage"},
                                    frame.getStackVariables().length + 3);
            t.row("_frame_size", frame.getFrameSize(), "", "", "");
            t.row("_local_size", frame.getLocalSize(), "", "", "");
            t.row("_param_size", frame.getParameterSize(), "", "", "");
            for (var v : frame.getStackVariables()) {
                var dt = v.getDataType();
                var storage = v.getVariableStorage();
                t.row(v.getName(), v.getStackOffset(), dt != null ? dt.getName() : "?",
                      v.getLength(), storage != null ? storage.toString() : "");
            }
            return t.build();
        });
    }
}
