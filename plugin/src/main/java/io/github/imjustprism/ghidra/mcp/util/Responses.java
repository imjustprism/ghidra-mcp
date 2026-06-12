package io.github.imjustprism.ghidra.mcp.util;

import io.github.imjustprism.ghidra.mcp.http.Page;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public final class Responses {

    public static final int MAX_BYTES = 200_000;

    public enum Fmt { TSV, CSV, JSON, VERBOSE }

    private Responses() {}

    public static Fmt pickFmt(Map<String, String> q) {
        var v = q == null ? null : q.get("fmt");
        if (v == null || v.isEmpty()) return Fmt.TSV;
        return switch (v.toLowerCase()) {
            case "csv" -> Fmt.CSV;
            case "json" -> Fmt.JSON;
            case "verbose", "plain", "text" -> Fmt.VERBOSE;
            default -> Fmt.TSV;
        };
    }

    public static String addr(Object a) {
        if (a == null) return "";
        var s = a.toString();
        if (s.length() > 2 && s.charAt(0) == '0' && (s.charAt(1) == 'x' || s.charAt(1) == 'X')) {
            return s.substring(2);
        }
        return s;
    }

    public static String cell(String s) {
        if (s == null) return "";
        var n = s.length();
        StringBuilder sb = null;
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            if (c == '\t' || c == '\n' || c == '\r' || c == '\\') {
                if (sb == null) {
                    sb = new StringBuilder(n + 8);
                    sb.append(s, 0, i);
                }
                switch (c) {
                    case '\t' -> sb.append("\\t");
                    case '\n' -> sb.append("\\n");
                    case '\r' -> sb.append("\\r");
                    case '\\' -> sb.append("\\\\");
                    default -> sb.append(c);
                }
            } else if (sb != null) {
                sb.append(c);
            }
        }
        return sb == null ? s : sb.toString();
    }

    public static final class Table {
        private final Fmt fmt;
        private final String[] cols;
        private final StringBuilder sb;
        private int emitted;
        private int total = -1;
        private boolean truncated;
        private boolean jsonFirst = true;

        private Table(Fmt fmt, String[] cols, int expectedRows) {
            this.fmt = fmt;
            this.cols = cols;
            this.sb = new StringBuilder(Math.min(MAX_BYTES, Math.max(256, expectedRows * 48)));
            header();
        }

        private void header() {
            switch (fmt) {
                case TSV -> {
                    sb.append("# format=tsv; addr=hex; cols=");
                    for (int i = 0; i < cols.length; i++) {
                        if (i > 0) sb.append(',');
                        sb.append(cols[i]);
                    }
                    sb.append('\n');
                }
                case CSV -> {
                    for (int i = 0; i < cols.length; i++) {
                        if (i > 0) sb.append(',');
                        sb.append(cols[i]);
                    }
                    sb.append('\n');
                }
                case JSON -> sb.append('[');
                case VERBOSE -> {}
            }
        }

        public Table row(Object... values) {
            if (truncated) return this;
            int mark = sb.length();
            switch (fmt) {
                case TSV -> {
                    for (int i = 0; i < values.length; i++) {
                        if (i > 0) sb.append('\t');
                        sb.append(cell(String.valueOf(values[i])));
                    }
                    sb.append('\n');
                }
                case CSV -> {
                    for (int i = 0; i < values.length; i++) {
                        if (i > 0) sb.append(',');
                        appendCsv(String.valueOf(values[i]));
                    }
                    sb.append('\n');
                }
                case JSON -> {
                    if (!jsonFirst) sb.append(',');
                    jsonFirst = false;
                    sb.append('{');
                    for (int i = 0; i < values.length && i < cols.length; i++) {
                        if (i > 0) sb.append(',');
                        sb.append('"').append(cols[i]).append("\":");
                        appendJsonValue(values[i]);
                    }
                    sb.append('}');
                }
                case VERBOSE -> {
                    for (int i = 0; i < values.length && i < cols.length; i++) {
                        if (i > 0) sb.append(' ');
                        sb.append(cols[i]).append('=').append(values[i]);
                    }
                    sb.append('\n');
                }
            }
            emitted++;
            if (sb.length() > MAX_BYTES) {
                sb.setLength(mark);
                truncated = true;
            }
            return this;
        }

        public Table total(int t) { this.total = t; return this; }

        private void appendCsv(String s) {
            if (s.indexOf(',') < 0 && s.indexOf('"') < 0 && s.indexOf('\n') < 0) {
                sb.append(s);
                return;
            }
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '"') sb.append('"');
                sb.append(c);
            }
            sb.append('"');
        }

        private void appendJsonValue(Object v) {
            if (v == null) { sb.append("null"); return; }
            if (v instanceof Number || v instanceof Boolean) { sb.append(v); return; }
            sb.append('"');
            var s = v.toString();
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"' -> sb.append("\\\"");
                    case '\\' -> sb.append("\\\\");
                    case '\n' -> sb.append("\\n");
                    case '\r' -> sb.append("\\r");
                    case '\t' -> sb.append("\\t");
                    default -> {
                        if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                        else sb.append(c);
                    }
                }
            }
            sb.append('"');
        }

        public String build() {
            switch (fmt) {
                case JSON -> sb.append(']');
                default -> {}
            }
            if (total >= 0 && fmt != Fmt.JSON) {
                sb.append("# total=").append(total).append('\n');
            }
            if (truncated) {
                sb.append("# ...truncated at ").append(MAX_BYTES).append(" bytes\n");
            }
            return sb.toString();
        }
    }

    public static Table table(Fmt fmt, String[] cols, int expectedRows) {
        return new Table(fmt, cols, expectedRows);
    }

    public static Table table(Map<String, String> q, String[] cols, int expectedRows) {
        return new Table(pickFmt(q), cols, expectedRows);
    }

    public static Table table(Page p, Map<String, String> q, String[] cols) {
        return new Table(pickFmt(q), cols, Math.min(p.limit(), 512));
    }

    public static String page(Map<String, String> q, Page p, String[] cols, List<Object[]> rows) {
        boolean includeAuto = "1".equals(q.get("include_auto"));
        var t = table(pickFmt(q), cols, Math.min(p.limit(), rows.size()));
        var w = new Window(p);
        for (var r : rows) {
            if (!includeAuto && r.length > 0 && isAutoName(String.valueOf(r[0]))) continue;
            if (!w.take()) continue;
            t.row(r);
        }
        return t.total(w.total()).build();
    }

    public static final class Window {
        private final int offset;
        private final int limit;
        private int seen;
        private int kept;

        public Window(Page p) {
            this.offset = Math.max(0, p.offset());
            this.limit = Math.max(0, p.limit());
        }

        public boolean take() {
            seen++;
            if (seen > offset && kept < limit) {
                kept++;
                return true;
            }
            return false;
        }

        public int total() {
            return seen;
        }
    }

    public static boolean isAutoName(String name) {
        if (name == null || name.length() < 5) return false;
        return name.startsWith("FUN_") || name.startsWith("LAB_")
                || name.startsWith("DAT_") || name.startsWith("SUB_")
                || name.startsWith("UNK_") || name.startsWith("OFF_");
    }

    public static String pageStream(Map<String, String> q, Page p, String col, Stream<String> s) {
        boolean includeAuto = "1".equals(q.get("include_auto"));
        var t = table(pickFmt(q), new String[]{col}, Math.min(Math.max(0, p.limit()), 512));
        var w = new Window(p);
        var it = s.iterator();
        while (it.hasNext()) {
            var v = it.next();
            if (v == null) continue;
            if (!includeAuto && isAutoName(v)) continue;
            if (!w.take()) continue;
            t.row(v);
        }
        return t.total(w.total()).build();
    }
}
