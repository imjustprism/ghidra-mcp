// Headless read-only HTTP bridge for ghidra-mcp. Serves currentProgram on
// 127.0.0.1:8080 in the format the Rust bridge relays verbatim to the LLM.
// Run via analyzeHeadless ... -process <binary> -readOnly -postScript ServeMcp.java
// Keeps running (blocks) so the bridge can connect. Kill the JVM to stop.
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import java.net.InetSocketAddress;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Executors;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class ServeMcp extends GhidraScript {
    private Program prog;
    private DecompInterface decomp;
    private volatile String dumpStatus = "idle";
    private volatile boolean dumping = false;

    @Override
    public void run() throws Exception {
        prog = currentProgram;
        decomp = new DecompInterface();
        decomp.openProgram(prog);

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 8080), 64);
        server.setExecutor(Executors.newSingleThreadExecutor()); // serialize: Ghidra API not thread-safe
        server.createContext("/", ex -> {
            String path = ex.getRequestURI().getPath();
            if (path.startsWith("/")) path = path.substring(1);
            Map<String, String> q = parse(ex.getRequestURI().getRawQuery());
            String body;
            try {
                body = route(path, q);
            } catch (Throwable t) {
                body = "ERROR: " + t;
            }
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(b); }
        });
        server.start();
        println("ServeMcp: HTTP bridge listening on 127.0.0.1:8080 for " + prog.getName());
        while (true) { Thread.sleep(3600000); }
    }

    private String route(String p, Map<String, String> q) throws Exception {
        int off = intp(q, "offset", 0), lim = intp(q, "limit", 100);
        switch (p) {
            case "program_info":
            case "program_metadata": return programInfo();
            case "list_open_programs": return listOpen();
            case "get_current_address": return prog.getImageBase().toString();
            case "get_current_function": { Function f = first(); return f == null ? "none" : f.getName() + " @ " + f.getEntryPoint(); }
            case "list_functions": return listFunctions(off, lim, !"0".equals(q.getOrDefault("with_address", "1")), "1".equals(q.get("include_auto")));
            case "searchFunctions": return searchFunctions(q.getOrDefault("query", ""), off, lim);
            case "get_function_by_address": return funcByAddr(q.get("address"));
            case "decompile": return decompile(q.getOrDefault("target", ""));
            case "disassemble_function": return disasm(q.get("address"));
            case "xrefs": return xrefs(q.getOrDefault("target", ""), q.getOrDefault("direction", "both"), off, lim);
            case "strings": return strings(q.getOrDefault("filter", ""), off, lim);
            case "imports": return imports(off, lim);
            case "exports":
            case "entry_points": return exports(off, lim);
            case "namespaces":
            case "classes":
            case "recover_rtti_classes":
            case "vtable_scan": return classes(off, lim);
            case "list_callers": return callers(pick(q, "address", "name", "target"), true);
            case "list_callees": return callers(pick(q, "address", "name", "target"), false);
            case "segments":
            case "sections_detailed": return segments();
            case "read_bytes":
            case "hex_dump": return readBytes(pick(q, "address"), intpAny(q, 64, "length", "size", "len", "count"));
            case "instruction_at": return instrAt(pick(q, "address"));
            case "function_string_refs": return funcStringRefs(pick(q, "address", "name", "target"));
            case "find_function_by_string": return findFuncByString(pick(q, "value", "query", "filter"), intpAny(q, 50, "max", "limit"));
            case "dump_all": return startDump(pick(q, "dir", "out"));
            case "dump_status": return dumpStatus;
            default: return "shim: endpoint '" + p + "' not implemented by the headless read-only bridge. "
                + "Available: program_info, program_metadata, list_open_programs, list_functions, searchFunctions, "
                + "get_function_by_address, decompile, disassemble_function, xrefs, strings, imports, exports, "
                + "namespaces/classes/recover_rtti_classes, list_callers, list_callees, segments, read_bytes, "
                + "hex_dump, instruction_at, function_string_refs, find_function_by_string. "
                + "Annotation/save/debugger/emulation endpoints are unavailable headless — record findings in the MD maps.";
        }
    }

    // ---- handlers ----
    private String programInfo() {
        StringBuilder s = new StringBuilder();
        s.append("name\t").append(prog.getName()).append('\n');
        s.append("languageID\t").append(prog.getLanguageID()).append('\n');
        s.append("processor\t").append(prog.getLanguage().getProcessor()).append('\n');
        s.append("addressSize\t").append(prog.getDefaultPointerSize() * 8).append('\n');
        s.append("imageBase\t").append(prog.getImageBase()).append('\n');
        s.append("executablePath\t").append(prog.getExecutablePath()).append('\n');
        s.append("sha256\t").append(prog.getExecutableSHA256()).append('\n');
        s.append("functionCount\t").append(prog.getFunctionManager().getFunctionCount()).append('\n');
        return s.toString();
    }

    private String listOpen() {
        return "name\tactive\tsha256\tpath\n" + prog.getName() + "\ttrue\t" + prog.getExecutableSHA256() + "\t" + prog.getExecutablePath() + "\n";
    }

    private String listFunctions(int off, int lim, boolean withAddr, boolean includeAuto) {
        List<String> rows = new ArrayList<>();
        for (Function f : prog.getFunctionManager().getFunctions(true)) {
            String n = f.getName();
            if (!includeAuto && n.startsWith("FUN_")) continue;
            rows.add(withAddr ? (n + "\t" + f.getEntryPoint()) : n);
        }
        return page(rows, off, lim, rows.size() + " functions" + (includeAuto ? "" : " (FUN_* hidden)"));
    }

    private String searchFunctions(String query, int off, int lim) {
        String ql = query.toLowerCase();
        List<String> rows = new ArrayList<>();
        for (Function f : prog.getFunctionManager().getFunctions(true))
            if (f.getName().toLowerCase().contains(ql)) rows.add(f.getName() + "\t" + f.getEntryPoint());
        return page(rows, off, lim, rows.size() + " matches for '" + query + "'");
    }

    private String funcByAddr(String a) {
        Address addr = addr(a);
        if (addr == null) return "invalid address: " + a;
        Function f = prog.getFunctionManager().getFunctionContaining(addr);
        if (f == null) return "no function at " + a;
        return f.getName() + " @ " + f.getEntryPoint() + "\nsignature: " + f.getSignature().getPrototypeString()
            + "\nbody: " + f.getBody().getMinAddress() + " - " + f.getBody().getMaxAddress();
    }

    private String decompile(String target) {
        Function f = resolve(target);
        if (f == null) return "function not found: " + target;
        DecompileResults r = decomp.decompileFunction(f, 60, TaskMonitor.DUMMY);
        if (r == null || !r.decompileCompleted()) return "decompile failed: " + (r == null ? "null" : r.getErrorMessage());
        return "// " + f.getName() + " @ " + f.getEntryPoint() + "\n" + r.getDecompiledFunction().getC();
    }

    private String disasm(String a) {
        Address addr = addr(a);
        if (addr == null) return "invalid address: " + a;
        Function f = prog.getFunctionManager().getFunctionContaining(addr);
        if (f == null) return "no function at " + a;
        StringBuilder s = new StringBuilder("// " + f.getName() + " @ " + f.getEntryPoint() + "\n");
        for (Instruction in : prog.getListing().getInstructions(f.getBody(), true)) {
            s.append(in.getAddress()).append("  ").append(in.toString()).append('\n');
        }
        return s.toString();
    }

    private String xrefs(String target, String dir, int off, int lim) {
        ReferenceManager rm = prog.getReferenceManager();
        List<String> rows = new ArrayList<>();
        Address addr = addr(target);
        if (addr == null) { Function f = resolve(target); if (f != null) addr = f.getEntryPoint(); }
        if (addr == null) return "target not found: " + target;
        if (dir.equals("from")) {
            for (Reference r : rm.getReferencesFrom(addr)) rows.add(r.getFromAddress() + " -> " + r.getToAddress() + " (" + r.getReferenceType() + ")");
        } else {
            for (Reference r : rm.getReferencesTo(addr)) {
                Function ff = prog.getFunctionManager().getFunctionContaining(r.getFromAddress());
                rows.add(r.getFromAddress() + " (" + (ff == null ? "?" : ff.getName()) + ") -> " + r.getToAddress() + " (" + r.getReferenceType() + ")");
            }
        }
        return page(rows, off, lim, rows.size() + " xrefs " + dir + " " + target);
    }

    private String strings(String filter, int off, int lim) {
        String fl = filter.toLowerCase();
        List<String> rows = new ArrayList<>();
        DataIterator it = prog.getListing().getDefinedData(true);
        while (it.hasNext()) {
            Data d = it.next();
            Object v = d.getValue();
            if (v instanceof String) {
                String s = (String) v;
                if (fl.isEmpty() || s.toLowerCase().contains(fl)) rows.add(d.getAddress() + "\t" + s.replace("\n", "\\n"));
            }
        }
        return page(rows, off, lim, rows.size() + " strings" + (filter.isEmpty() ? "" : " matching '" + filter + "'"));
    }

    private String imports(int off, int lim) {
        List<String> rows = new ArrayList<>();
        for (Symbol s : prog.getSymbolTable().getExternalSymbols())
            rows.add(s.getParentNamespace().getName() + "!" + s.getName() + "\t" + s.getAddress());
        Collections.sort(rows);
        return page(rows, off, lim, rows.size() + " imports");
    }

    private String exports(int off, int lim) {
        List<String> rows = new ArrayList<>();
        AddressIterator it = prog.getSymbolTable().getExternalEntryPointIterator();
        while (it.hasNext()) {
            Address a = it.next();
            Symbol s = prog.getSymbolTable().getPrimarySymbol(a);
            rows.add((s == null ? "?" : s.getName()) + "\t" + a);
        }
        return page(rows, off, lim, rows.size() + " entry points/exports");
    }

    private String classes(int off, int lim) {
        List<String> rows = new ArrayList<>();
        java.util.Iterator<GhidraClass> it = prog.getSymbolTable().getClassNamespaces();
        while (it.hasNext()) rows.add(it.next().getName(true));
        Collections.sort(rows);
        return page(rows, off, lim, rows.size() + " classes/namespaces");
    }

    private String callers(String a, boolean callers) {
        Function f = resolveAny(a);
        if (f == null) return "function not found: " + a;
        Set<Function> set = callers ? f.getCallingFunctions(TaskMonitor.DUMMY) : f.getCalledFunctions(TaskMonitor.DUMMY);
        List<String> rows = new ArrayList<>();
        for (Function g : set) rows.add(g.getName() + "\t" + g.getEntryPoint());
        Collections.sort(rows);
        return page(rows, 0, 1000, (callers ? "callers of " : "callees of ") + f.getName());
    }

    private String segments() {
        StringBuilder s = new StringBuilder("name\tstart\tend\tsize\trwx\n");
        for (MemoryBlock b : prog.getMemory().getBlocks())
            s.append(b.getName()).append('\t').append(b.getStart()).append('\t').append(b.getEnd()).append('\t')
             .append("0x").append(Long.toHexString(b.getSize())).append('\t')
             .append(b.isRead() ? "R" : "-").append(b.isWrite() ? "W" : "-").append(b.isExecute() ? "X" : "-").append('\n');
        return s.toString();
    }

    private String readBytes(String a, int len) throws Exception {
        Address addr = addr(a);
        if (addr == null) return "invalid address: " + a;
        len = Math.min(len, 4096);
        byte[] buf = new byte[len];
        int n = prog.getMemory().getBytes(addr, buf);
        StringBuilder s = new StringBuilder(a + " (" + n + " bytes)\n");
        for (int i = 0; i < n; i++) { s.append(String.format("%02x ", buf[i] & 0xff)); if ((i & 15) == 15) s.append('\n'); }
        return s.toString();
    }

    private String instrAt(String a) {
        Address addr = addr(a);
        if (addr == null) return "invalid address: " + a;
        Instruction in = prog.getListing().getInstructionAt(addr);
        return in == null ? "no instruction at " + a : in.getAddress() + "  " + in.toString();
    }

    private String funcStringRefs(String a) {
        Function f = resolveAny(a);
        if (f == null) return "function not found: " + a;
        List<String> rows = new ArrayList<>();
        ReferenceManager rm = prog.getReferenceManager();
        for (Instruction in : prog.getListing().getInstructions(f.getBody(), true))
            for (Reference r : rm.getReferencesFrom(in.getAddress())) {
                Data d = prog.getListing().getDefinedDataAt(r.getToAddress());
                if (d != null && d.getValue() instanceof String) rows.add(in.getAddress() + "\t" + d.getValue());
            }
        return page(rows, 0, 1000, rows.size() + " string refs in " + f.getName());
    }

    private String findFuncByString(String query, int lim) {
        if (query.isEmpty()) return "query required";
        String ql = query.toLowerCase();
        Set<String> funcs = new LinkedHashSet<>();
        ReferenceManager rm = prog.getReferenceManager();
        DataIterator it = prog.getListing().getDefinedData(true);
        while (it.hasNext()) {
            Data d = it.next();
            Object v = d.getValue();
            if (v instanceof String && ((String) v).toLowerCase().contains(ql)) {
                for (Reference r : rm.getReferencesTo(d.getAddress())) {
                    Function f = prog.getFunctionManager().getFunctionContaining(r.getFromAddress());
                    if (f != null) funcs.add(f.getName() + "\t" + f.getEntryPoint() + "\t<- \"" + v + "\"");
                }
            }
            if (funcs.size() >= lim) break;
        }
        return funcs.isEmpty() ? "no function references a string matching '" + query + "'" : String.join("\n", funcs);
    }

    // ---- full dump (background thread; serves live queries meanwhile) ----
    private String startDump(String dir) {
        if (dumping) return "already running: " + dumpStatus;
        final String out = (dir == null || dir.isBlank()) ? "D:/Projects/ghidra-mcp/RE-MD/findings/alicia-dumps/full" : dir;
        dumping = true;
        dumpStatus = "starting -> " + out;
        Thread th = new Thread(() -> {
            try { runDump(out); } catch (Throwable t) { dumpStatus = "ERROR: " + t; } finally { dumping = false; }
        }, "mcp-dump");
        th.setDaemon(true);
        th.start();
        return "dump started -> " + out + " (poll /dump_status)";
    }

    private void writeFile(String path, String content) throws Exception {
        try (java.io.PrintWriter w = new java.io.PrintWriter(new java.io.BufferedWriter(new java.io.FileWriter(path)))) { w.print(content); }
    }

    private void runDump(String out) throws Exception {
        new java.io.File(out).mkdirs();
        long t0 = System.currentTimeMillis();
        dumpStatus = "inventory...";
        List<Function> funcs = new ArrayList<>();
        for (Function f : prog.getFunctionManager().getFunctions(true)) funcs.add(f);
        try (java.io.PrintWriter w = new java.io.PrintWriter(new java.io.BufferedWriter(new java.io.FileWriter(out + "/functions.tsv")))) {
            w.println("address\tname\tsize\tnamespace");
            for (Function f : funcs) w.println(f.getEntryPoint() + "\t" + f.getName() + "\t" + f.getBody().getNumAddresses() + "\t" + f.getParentNamespace().getName(true));
        }
        writeFile(out + "/strings.tsv", strings("", 0, Integer.MAX_VALUE));
        writeFile(out + "/imports.tsv", imports(0, Integer.MAX_VALUE));
        writeFile(out + "/exports.tsv", exports(0, Integer.MAX_VALUE));
        writeFile(out + "/classes.tsv", classes(0, Integer.MAX_VALUE));
        writeFile(out + "/segments.tsv", segments());
        DecompInterface di = new DecompInterface();
        di.openProgram(prog);
        int n = funcs.size(), done = 0, shard = -1, inShard = 0, failed = 0;
        final int SHARD = 4000;
        java.io.PrintWriter cw = null;
        try {
            for (Function f : funcs) {
                if (cw == null || inShard >= SHARD) {
                    if (cw != null) cw.close();
                    shard++; inShard = 0;
                    cw = new java.io.PrintWriter(new java.io.BufferedWriter(new java.io.FileWriter(String.format("%s/decomp_%04d.c", out, shard))));
                }
                cw.println("// ===== " + f.getName() + " @ " + f.getEntryPoint() + " (size " + f.getBody().getNumAddresses() + ") =====");
                try {
                    DecompileResults r = di.decompileFunction(f, 30, TaskMonitor.DUMMY);
                    if (r != null && r.decompileCompleted()) cw.println(r.getDecompiledFunction().getC());
                    else { cw.println("// <decompile failed: " + (r == null ? "null" : r.getErrorMessage()) + ">"); failed++; }
                } catch (Throwable t) { cw.println("// <exception: " + t + ">"); failed++; }
                cw.println();
                inShard++; done++;
                if ((done % 200) == 0) dumpStatus = "decompiling " + done + "/" + n + " (" + ((System.currentTimeMillis() - t0) / 1000) + "s, shard " + shard + ", " + failed + " failed)";
            }
        } finally { if (cw != null) cw.close(); di.dispose(); }
        dumpStatus = "DONE: " + n + " functions, " + (shard + 1) + " shards, " + failed + " failed, " + ((System.currentTimeMillis() - t0) / 1000) + "s -> " + out;
    }

    // ---- helpers ----
    private Function first() { FunctionIterator it = prog.getFunctionManager().getFunctions(true); return it.hasNext() ? it.next() : null; }
    private Address addr(String s) { if (s == null || s.isBlank()) return null; try { return prog.getAddressFactory().getAddress(s.trim()); } catch (Exception e) { return null; } }
    private Function resolve(String target) {
        if (target == null || target.isBlank()) return null;
        Address a = addr(target);
        if (a != null) { Function f = prog.getFunctionManager().getFunctionContaining(a); if (f != null) return f; }
        Function exact = null, partial = null;
        for (Function f : prog.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(target)) { exact = f; break; }
            if (partial == null && f.getName().contains(target)) partial = f;
        }
        return exact != null ? exact : partial;
    }
    private Function resolveAny(String s) { Address a = addr(s); if (a != null) { Function f = prog.getFunctionManager().getFunctionContaining(a); if (f != null) return f; } return resolve(s); }
    private String page(List<String> rows, int off, int lim, String header) {
        int end = Math.min(rows.size(), off + lim);
        StringBuilder s = new StringBuilder("# " + header + " (showing " + off + ".." + end + " of " + rows.size() + ")\n");
        for (int i = off; i < end; i++) s.append(rows.get(i)).append('\n');
        return s.toString();
    }
    private int intp(Map<String, String> q, String k, int d) { try { String v = q.get(k); return v == null ? d : Integer.parseInt(v.trim()); } catch (Exception e) { return d; } }
    private String pick(Map<String, String> q, String... keys) { for (String k : keys) { String v = q.get(k); if (v != null && !v.isBlank()) return v; } return null; }
    private int intpAny(Map<String, String> q, int d, String... keys) { for (String k : keys) { String v = q.get(k); if (v != null) try { return Integer.parseInt(v.trim()); } catch (Exception ignored) {} } return d; }
    private Map<String, String> parse(String raw) {
        Map<String, String> m = new HashMap<>();
        if (raw == null) return m;
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) continue;
            try { m.put(URLDecoder.decode(pair.substring(0, eq), "UTF-8"), URLDecoder.decode(pair.substring(eq + 1), "UTF-8")); } catch (Exception ignored) {}
        }
        return m;
    }
}
