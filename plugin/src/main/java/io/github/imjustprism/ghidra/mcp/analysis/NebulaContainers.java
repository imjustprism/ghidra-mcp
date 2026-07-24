package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.DecompileCache;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class NebulaContainers {

    private static final Pattern FIELD_SIZE = Pattern.compile(
            "this->([A-Za-z_][A-Za-z0-9_]*)\\.Size\\(\\)", Pattern.CASE_INSENSITIVE);
    private static final Pattern BASE_PLUS = Pattern.compile(
            "\\(\\s*(?:int|uint|longlong|ulonglong|undefined4|undefined8)\\s*\\*\\s*\\)\\s*"
                    + "\\(\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*\\+\\s*(0x[0-9a-fA-F]+|\\d+)\\s*\\)");
    private static final Pattern MEMBER_PLUS = Pattern.compile(
            "([A-Za-z_][A-Za-z0-9_]*)\\s*\\+\\s*(0x[0-9a-fA-F]+|\\d+)");
    private static final Pattern INDEX_STRIDE = Pattern.compile(
            "\\*\\s*\\([^)]*\\)\\s*\\+\\s*\\([^)]*\\)\\s*\\*\\s*(\\d+)");
    private static final Pattern HEADER = Pattern.compile(
            "(fixedarray|array|dictionary|hashtable)\\.h", Pattern.CASE_INSENSITIVE);

    private NebulaContainers() {}

    public static String layout(PluginContext ctx, String addr, String baseVar, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("no function at " + addr);
            var c = DecompileCache.decompile(program, func);
            var base = baseVar == null || baseVar.isBlank() ? detectBase(c) : baseVar.trim();
            var rows = new LinkedHashMap<String, String[]>();

            for (var m : FIELD_SIZE.matcher(c).results().toList()) {
                var name = m.group(1);
                long off = nearestOffsetBefore(c, m.start(), base);
                var key = name + "@" + Long.toHexString(off);
                rows.putIfAbsent(key, new String[]{
                        "array", name, hex(off), "0x8", "8", "this->" + name + ".Size()", "size@+0 elems@+8 (FixedArray heuristic)"
                });
            }

            if (HEADER.matcher(c).find() || c.contains("fixedarray.h") || c.contains("elements &&")) {
                for (var m : BASE_PLUS.matcher(c).results().toList()) {
                    if (!m.group(1).equals(base) && !m.group(1).matches("param_\\d+|this|unaff_.*")) continue;
                    long off = parseOff(m.group(2));
                    var key = "container@" + Long.toHexString(off);
                    rows.putIfAbsent(key, new String[]{
                            kindFromSource(c), "(anon)", hex(off), "0x8", "8",
                            m.group(0), "base+" + hex(off) + " treated as Util::FixedArray*"
                    });
                }
            }

            for (var call : func.getCalledFunctions(new ghidra.util.task.ConsoleTaskMonitor())) {
                String cc;
                try {
                    cc = DecompileCache.decompile(program, call);
                } catch (RuntimeException e) {
                    continue;
                }
                if (!cc.contains("fixedarray.h") && !cc.contains("this->elements") && !cc.contains("this->size")) {
                    continue;
                }
                int stride = 8;
                Matcher sm = INDEX_STRIDE.matcher(cc);
                if (sm.find()) stride = Integer.parseInt(sm.group(1));
                long sizeOff = 0;
                long elemsOff = 8;
                if (cc.contains("param_1 + 2") || cc.contains("(param_1 + 2)")) elemsOff = 8;
                for (var m : BASE_PLUS.matcher(c).results().toList()) {
                    long off = parseOff(m.group(2));
                    var key = "via_" + call.getName() + "@" + Long.toHexString(off);
                    rows.putIfAbsent(key, new String[]{
                            "fixedarray", fieldNear(c, m.start()), hex(off), hex(elemsOff),
                            Integer.toString(stride), call.getName(),
                            "indexer " + call.getName() + " size@" + hex(sizeOff) + " elems@" + hex(elemsOff)
                                    + " stride=" + stride
                    });
                }
            }

            if (rows.isEmpty()) {
                return "# no Nebula3 Array/FixedArray/Dictionary layout recovered in "
                        + func.getName() + " (base_var=" + base + ")\n"
                        + "# tip: pass a function that asserts this->field.Size() or calls FixedArray operator[]\n";
            }
            var t = Responses.table(q, new String[]{
                    "kind", "field", "size_off", "elems_off", "stride", "evidence", "layout"
            }, rows.size());
            for (var r : rows.values()) t.row((Object[]) r);
            return "# nebula_container_layout " + func.getName() + " base=" + base + "\n" + t.total(rows.size()).build();
        });
    }

    private static String detectBase(String c) {
        if (c.contains("param_1")) return "param_1";
        if (c.contains("this")) return "this";
        Matcher m = Pattern.compile("\\b(unaff_[A-Za-z0-9_]+|param_\\d+)\\b").matcher(c);
        return m.find() ? m.group(1) : "param_1";
    }

    private static String kindFromSource(String c) {
        if (c.toLowerCase().contains("dictionary")) return "dictionary";
        if (c.toLowerCase().contains("hashtable")) return "hashtable";
        if (c.toLowerCase().contains("fixedarray")) return "fixedarray";
        return "array";
    }

    private static String fieldNear(String c, int pos) {
        int from = Math.max(0, pos - 200);
        Matcher m = FIELD_SIZE.matcher(c.substring(from, Math.min(c.length(), pos + 80)));
        return m.find() ? m.group(1) : "";
    }

    private static long nearestOffsetBefore(String c, int pos, String base) {
        int from = Math.max(0, pos - 400);
        String win = c.substring(from, pos);
        long best = -1;
        int bestAt = -1;
        Matcher m = BASE_PLUS.matcher(win);
        while (m.find()) {
            if (!m.group(1).equals(base) && !m.group(1).matches("param_\\d+|this")) continue;
            best = parseOff(m.group(2));
            bestAt = m.start();
        }
        if (bestAt >= 0) return best;
        m = MEMBER_PLUS.matcher(win);
        while (m.find()) {
            if (!m.group(1).equals(base)) continue;
            best = parseOff(m.group(2));
        }
        return best < 0 ? 0 : best;
    }

    private static long parseOff(String s) {
        if (s.startsWith("0x") || s.startsWith("0X")) return Long.parseLong(s.substring(2), 16);
        return Long.parseLong(s);
    }

    private static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }
}
