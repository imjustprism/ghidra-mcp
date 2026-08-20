package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public final class ExtractIocs {

    private record Ioc(String category, Pattern pattern) {}

    private static final List<Ioc> IOCS = List.of(
            new Ioc("url", Pattern.compile("\\b[a-z][a-z0-9+.-]*://[\\w.-]+(?::\\d+)?(?:/[^\\s\"'<>]*)?",
                    Pattern.CASE_INSENSITIVE)),
            new Ioc("api_path", Pattern.compile("/api/[A-Za-z0-9_./?-]{2,80}")),
            new Ioc("bearer", Pattern.compile("Authorization:\\s*Bearer\\s+\\S+", Pattern.CASE_INSENSITIVE)),
            new Ioc("jwt", Pattern.compile("\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b")),
            new Ioc("ipv4", Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b")),
            new Ioc("email", Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b")),
            new Ioc("registry", Pattern.compile("\\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)[\\\\/][^\\s\"'<>]+",
                    Pattern.CASE_INSENSITIVE)),
            new Ioc("win_path", Pattern.compile("\\b[A-Za-z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\?)+")),
            new Ioc("unc_path", Pattern.compile("\\\\\\\\[A-Za-z0-9._-]+\\\\[^\\s\"'<>]+")),
            new Ioc("guid", Pattern.compile("\\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\\}")),
            new Ioc("btc", Pattern.compile("\\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\\b")));

    private static final List<Ioc> RAW_IOCS = List.of(
            new Ioc("url", Pattern.compile("https?://[\\w.-]+(?::\\d+)?(?:/[^\\s\"']{0,80})?",
                    Pattern.CASE_INSENSITIVE)),
            new Ioc("api_path", Pattern.compile("/api/[A-Za-z0-9_./?-]{2,80}")));

    private ExtractIocs() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        String scope = q.getOrDefault("scope", "defined").trim().toLowerCase(Locale.ROOT);
        boolean defined = !"raw".equals(scope);
        boolean raw = "raw".equals(scope) || "both".equals(scope);
        return ctx.withProgram(program -> {
            var t = Responses.table(p, q, new String[]{"category", "addr", "value"});
            var w = new Responses.Window(p);
            if (defined) scanDefined(program, t, w);
            if (raw) scanRaw(program, t, w);
            return t.total(w.total()).build();
        });
    }

    private static void scanDefined(Program program, Responses.Table t, Responses.Window w) {
        var it = program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            var data = it.next();
            if (data == null || !DataTypes.isStringLike(data)) continue;
            var value = data.getValue() != null ? data.getValue().toString() : "";
            emit(IOCS, value, Responses.addr(data.getAddress()), t, w);
        }
    }

    private static void scanRaw(Program program, Responses.Table t, Responses.Window w) {
        var mem = program.getMemory();
        for (var block : mem.getBlocks()) {
            if (block.isExecute() || !block.isInitialized()) continue;
            long size = block.getSize();
            if (size <= 0 || size > 8_000_000) continue;
            int n = (int) size;
            var buf = new byte[n];
            try {
                mem.getBytes(block.getStart(), buf);
            } catch (MemoryAccessException e) {
                continue;
            }
            scanBuf(buf, false, block.getStart(), t, w);
            scanBuf(buf, true, block.getStart(), t, w);
        }
    }

    private static void scanBuf(byte[] buf, boolean utf16, Address base, Responses.Table t,
                                Responses.Window w) {
        var sb = new StringBuilder();
        int runAt = -1;
        int i = 0;
        int step = utf16 ? 2 : 1;
        while (i + (utf16 ? 1 : 0) < buf.length) {
            int b = buf[i] & 0xFF;
            boolean ok;
            if (utf16) {
                ok = buf[i + 1] == 0 && ((b >= 0x20 && b < 0x7F) || b == '/' || b == ':');
            } else {
                ok = (b >= 0x20 && b < 0x7F);
            }
            if (ok) {
                if (sb.isEmpty()) runAt = i;
                sb.append((char) b);
            } else {
                flushRaw(sb, runAt, base, t, w);
                sb.setLength(0);
            }
            i += step;
        }
        flushRaw(sb, runAt, base, t, w);
    }

    private static void flushRaw(StringBuilder sb, int runAt, Address base, Responses.Table t,
                                 Responses.Window w) {
        if (sb.length() < 6 || runAt < 0) return;
        emit(RAW_IOCS, sb.toString(), Responses.addr(base.add(runAt)), t, w);
    }

    private static void emit(List<Ioc> iocs, String value, String addr, Responses.Table t,
                             Responses.Window w) {
        if (value.length() < 4) return;
        for (var ioc : iocs) {
            var m = ioc.pattern().matcher(value);
            while (m.find()) {
                if (!w.take()) continue;
                t.row(ioc.category(), addr, Responses.cell(m.group()));
            }
        }
    }
}
