package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import io.github.imjustprism.ghidra.mcp.analysis.Entropy;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Programs;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.Map;
import java.util.TreeSet;

public final class ListingHandlers {

    private final PluginContext ctx;

    public ListingHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    public void register(RouteTable routes) {
        routes.getPage("/methods", this::listFunctionNames);
        routes.getPage("/classes", this::listClassNames);
        routes.getPage("/segments", this::listSegments);
        routes.getPage("/imports", this::listImports);
        routes.getPage("/exports", this::listExports);
        routes.getPage("/namespaces", this::listNamespaces);
        routes.getPage("/data", this::listDefinedData);
        routes.getPage("/sections_detailed", this::listSectionsDetailed);
        routes.getPage("/entry_points", this::listEntryPoints);
        routes.getQuery("/strings", q -> listStrings(Page.from(q), q));
        routes.getQuery("/relocations", q -> listRelocations(Page.from(q), q));
    }

    public String listRelocations(Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var rt = program.getRelocationTable();
            var rows = new java.util.ArrayList<Object[]>();
            long off = p.offset();
            long lim = p.limit();
            long total = 0;
            for (var it = rt.getRelocations(); it.hasNext(); ) {
                var r = it.next();
                if (total >= off && rows.size() < lim) {
                    var sym = r.getSymbolName();
                    rows.add(new Object[]{Responses.addr(r.getAddress()),
                            "0x" + Integer.toHexString(r.getType()), sym != null ? sym : ""});
                }
                total++;
            }
            var t = Responses.table(p, q, new String[]{"address", "type", "symbol"});
            for (var row : rows) {
                t.row(row);
            }
            return t.total((int) Math.min(total, Integer.MAX_VALUE)).build();
        });
    }

    public String listFunctionNames(Page p, Map<String, String> q) {
        return ctx.withProgram(program ->
                Responses.pageStream(q, p, "fn", Programs.functions(program).map(Function::getName)));
    }

    public String listClassNames(Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var names = new TreeSet<String>();
            for (var s : program.getSymbolTable().getAllSymbols(true)) {
                var ns = s.getParentNamespace();
                if (ns != null && !ns.isGlobal()) names.add(ns.getName());
            }
            return Responses.pageStream(q, p, "class", names.stream());
        });
    }

    public String listSegments(Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var t = Responses.table(p, q, new String[]{"name", "start", "end"});
            var w = new Responses.Window(p);
            for (var b : program.getMemory().getBlocks()) {
                if (!w.take()) continue;
                t.row(b.getName(), Responses.addr(b.getStart()), Responses.addr(b.getEnd()));
            }
            return t.total(w.total()).build();
        });
    }

    public String listSectionsDetailed(Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var t = Responses.table(p, q, new String[]{"name", "start", "end", "size", "perms", "entropy"});
            var w = new Responses.Window(p);
            for (var b : program.getMemory().getBlocks()) {
                if (!w.take()) continue;
                var perms = new char[4];
                perms[0] = b.isRead() ? 'R' : '-';
                perms[1] = b.isWrite() ? 'W' : '-';
                perms[2] = b.isExecute() ? 'X' : '-';
                perms[3] = b.isInitialized() ? 'I' : '-';
                t.row(b.getName(), Responses.addr(b.getStart()), Responses.addr(b.getEnd()),
                      b.getSize(), new String(perms),
                      "%.2f".formatted(Entropy.blockEntropy(b)));
            }
            return t.total(w.total()).build();
        });
    }

    public String listImports(Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var t = Responses.table(p, q, new String[]{"name", "addr"});
            var w = new Responses.Window(p);
            for (var s : program.getSymbolTable().getExternalSymbols()) {
                if (!w.take()) continue;
                t.row(s.getName(), Responses.addr(s.getAddress()));
            }
            return t.total(w.total()).build();
        });
    }

    public String listExports(Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var t = Responses.table(p, q, new String[]{"name", "addr"});
            var w = new Responses.Window(p);
            for (var s : (Iterable<Symbol>) () -> program.getSymbolTable().getAllSymbols(true)) {
                if (!s.isExternalEntryPoint()) continue;
                if (!w.take()) continue;
                t.row(s.getName(), Responses.addr(s.getAddress()));
            }
            return t.total(w.total()).build();
        });
    }

    public String listEntryPoints(Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var t = Responses.table(p, q, new String[]{"addr", "name"});
            var w = new Responses.Window(p);
            var st = program.getSymbolTable();
            for (var it = st.getExternalEntryPointIterator(); it.hasNext(); ) {
                var addr = it.next();
                if (!w.take()) continue;
                var sym = st.getPrimarySymbol(addr);
                t.row(Responses.addr(addr), sym != null ? sym.getName() : "");
            }
            return t.total(w.total()).build();
        });
    }

    public String listNamespaces(Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var names = new TreeSet<String>();
            for (var s : program.getSymbolTable().getAllSymbols(true)) {
                var ns = s.getParentNamespace();
                if (ns != null && !(ns instanceof GlobalNamespace)) names.add(ns.getName());
            }
            return Responses.pageStream(q, p, "ns", names.stream());
        });
    }

    public String listDefinedData(Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var t = Responses.table(p, q, new String[]{"addr", "label", "value"});
            boolean includeAuto = "1".equals(q.get("include_auto"));
            var w = new Responses.Window(p);
            var listing = program.getListing();
            for (var block : program.getMemory().getBlocks()) {
                var it = listing.getDefinedData(block.getStart(), true);
                while (it.hasNext()) {
                    var data = it.next();
                    if (!block.contains(data.getAddress())) continue;
                    var label = data.getLabel();
                    if (!includeAuto && (label == null || Responses.isAutoName(label))) continue;
                    if (!w.take()) continue;
                    t.row(Responses.addr(data.getAddress()),
                          label != null ? label : "",
                          data.getDefaultValueRepresentation());
                }
            }
            return t.total(w.total()).build();
        });
    }

    public String listStrings(Page p, Map<String, String> q) {
        var filter = q.get("filter");
        return ctx.withProgram(program -> {
            var needle = filter == null || filter.isBlank() ? null : filter.toLowerCase();
            var t = Responses.table(p, q, new String[]{"addr", "value"});
            var w = new Responses.Window(p);
            var it = program.getListing().getDefinedData(true);
            while (it.hasNext()) {
                var data = it.next();
                if (data == null || !DataTypes.isStringLike(data)) continue;
                var value = data.getValue() != null ? data.getValue().toString() : "";
                if (needle != null && !value.toLowerCase().contains(needle)) continue;
                if (!w.take()) continue;
                t.row(Responses.addr(data.getAddress()), Strings.escapeString(value));
            }
            return t.total(w.total()).build();
        });
    }
}
