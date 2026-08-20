package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/** Export recovered + defined IOCs as YARA or a flat table. */
public final class IocExport {

    private static final Pattern HOST = Pattern.compile(
            "\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:com|net|org|io|gg|dev|app|xyz|ru|cn)\\b",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern API = Pattern.compile("/api/[A-Za-z0-9_./?-]{2,60}");
    private static final Pattern GUID = Pattern.compile(
            "\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\\}");
    private static final Pattern MUTEX = Pattern.compile("(?:Global|Local)\\\\[A-Za-z0-9_\\-{}]{6,80}");

    private IocExport() {}

    public static String export(PluginContext ctx, String format, String ruleName, boolean deep,
                                Page p, Map<String, String> q) {
        String fmt = format == null || format.isBlank() ? "yara" : format.trim().toLowerCase(Locale.ROOT);
        return ctx.withProgram(program -> {
            var iocs = collect(program, deep);
            if ("tsv".equals(fmt) || "json".equals(fmt) || "csv".equals(fmt)) {
                var t = Responses.table(p, q, new String[]{"kind", "value"});
                var w = new Responses.Window(p);
                for (var i : iocs) {
                    if (!w.take()) continue;
                    t.row(i.kind, Strings.escapeString(i.value));
                }
                return t.total(w.total()).build();
            }
            return renderYara(program, ruleName, iocs);
        });
    }

    static String yaraEscape(String s) {
        var sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c >= 32 && c < 127) sb.append(c);
                    else sb.append(String.format(Locale.ROOT, "\\x%02x", (int) c & 0xFF));
                }
            }
        }
        return sb.toString();
    }

    static String ident(String name) {
        if (name == null || name.isBlank()) return "GhidraMcpSample";
        var sb = new StringBuilder();
        char f = name.charAt(0);
        if (!Character.isLetter(f) && f != '_') sb.append('R');
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            sb.append(Character.isLetterOrDigit(c) || c == '_' ? c : '_');
        }
        return sb.toString();
    }

    static List<Ioc> collect(Program program, boolean deep) {
        var out = new ArrayList<Ioc>();
        var seen = new LinkedHashSet<String>();
        var sha = program.getExecutableSHA256();
        if (sha != null && !sha.isBlank()) add(out, seen, "sha256", sha);

        var it = program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            var d = it.next();
            if (d == null || !DataTypes.isStringLike(d) || d.getValue() == null) continue;
            harvest(d.getValue().toString(), out, seen);
        }
        if (deep) {
            for (var h : HiddenStrings.scanProgram(program, "auto", 6)) {
                harvest(h.value(), out, seen);
            }
        }
        add(out, seen, "const", "splitmix64_golden");
        return out;
    }

    static void harvest(String s, List<Ioc> out, LinkedHashSet<String> seen) {
        if (s == null || s.length() < 4) return;
        var m = HOST.matcher(s);
        while (m.find()) add(out, seen, "host", m.group());
        var a = API.matcher(s);
        while (a.find()) add(out, seen, "api_path", a.group());
        var g = GUID.matcher(s);
        while (g.find()) add(out, seen, "guid", g.group());
        var x = MUTEX.matcher(s);
        while (x.find()) add(out, seen, "mutex", x.group());
        if (s.startsWith("http://") || s.startsWith("https://")) add(out, seen, "url", s);
        if (s.length() >= 8 && s.length() <= 80 && looksUnique(s)) add(out, seen, "string", s);
    }

    static boolean looksUnique(String s) {
        int letters = 0;
        for (int i = 0; i < s.length(); i++) if (Character.isLetter(s.charAt(i))) letters++;
        if (letters < 4) return false;
        var low = s.toLowerCase(Locale.ROOT);
        return !low.startsWith("basic_string") && !low.contains("std::") && !low.contains("imgui")
                && !low.contains("warning");
    }

    private static void add(List<Ioc> out, LinkedHashSet<String> seen, String kind, String value) {
        if (seen.add(kind + "|" + value)) out.add(new Ioc(kind, value));
    }

    private static String renderYara(Program program, String ruleName, List<Ioc> iocs) {
        var name = ident(ruleName != null && !ruleName.isBlank() ? ruleName : program.getName());
        var sb = new StringBuilder(2048);
        sb.append("rule ").append(name).append(" {\n");
        sb.append("  meta:\n");
        sb.append("    generator = \"ghidra-mcp export_yara\"\n");
        var sha = program.getExecutableSHA256();
        if (sha != null) sb.append("    sha256 = \"").append(yaraEscape(sha)).append("\"\n");
        sb.append("  strings:\n");
        int i = 0;
        for (var ioc : iocs) {
            if ("sha256".equals(ioc.kind) || "const".equals(ioc.kind)) continue;
            if (ioc.value.length() < 4) continue;
            sb.append("    $s").append(i++).append(" = \"").append(yaraEscape(ioc.value)).append("\" ascii wide\n");
            if (i >= 40) break;
        }
        sb.append("    $splitmix = { 15 7C 4A 7F B9 79 E3 9E }\n");
        sb.append("  condition:\n");
        sb.append("    uint16(0) == 0x5A4D and (any of ($s*) or $splitmix)\n");
        sb.append("}\n");
        return sb.toString();
    }

    record Ioc(String kind, String value) {}
}
