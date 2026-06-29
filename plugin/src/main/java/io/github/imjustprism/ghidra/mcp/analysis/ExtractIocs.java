package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public final class ExtractIocs {

    private record Ioc(String category, Pattern pattern) {}

    private static final List<Ioc> IOCS = List.of(
            new Ioc("url", Pattern.compile("\\b[a-z][a-z0-9+.-]*://[\\w.-]+(?::\\d+)?(?:/[^\\s\"'<>]*)?",
                    Pattern.CASE_INSENSITIVE)),
            new Ioc("ipv4", Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b")),
            new Ioc("email", Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b")),
            new Ioc("registry", Pattern.compile("\\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)[\\\\/][^\\s\"'<>]+",
                    Pattern.CASE_INSENSITIVE)),
            new Ioc("win_path", Pattern.compile("\\b[A-Za-z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\?)+")),
            new Ioc("unc_path", Pattern.compile("\\\\\\\\[A-Za-z0-9._-]+\\\\[^\\s\"'<>]+")),
            new Ioc("guid", Pattern.compile("\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\\}")),
            new Ioc("btc", Pattern.compile("\\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\\b")));

    private ExtractIocs() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var t = Responses.table(p, q, new String[]{"category", "addr", "value"});
            var w = new Responses.Window(p);
            var it = program.getListing().getDefinedData(true);
            while (it.hasNext()) {
                var data = it.next();
                if (data == null || !DataTypes.isStringLike(data)) continue;
                var value = data.getValue() != null ? data.getValue().toString() : "";
                if (value.length() < 4) continue;
                for (var ioc : IOCS) {
                    var m = ioc.pattern().matcher(value);
                    while (m.find()) {
                        if (!w.take()) continue;
                        t.row(ioc.category(), Responses.addr(data.getAddress()),
                                Responses.cell(m.group()));
                    }
                }
            }
            return t.total(w.total()).build();
        });
    }
}
