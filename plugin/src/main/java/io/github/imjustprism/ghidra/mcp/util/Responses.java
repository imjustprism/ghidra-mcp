package io.github.imjustprism.ghidra.mcp.util;

import io.github.imjustprism.ghidra.mcp.http.Http;
import io.github.imjustprism.ghidra.mcp.http.Page;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
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
        /** Column indices to emit, in the order asked for; null means all of them. */
        private final int[] keep;
        /** {@code grep=} regex applied to the whole row before it is emitted. */
        private final Pattern rowFilter;
        /** {@code count=1}: report totals and suppress the rows entirely. */
        private final boolean countOnly;
        private final int maxBytes;
        /**
         * The caller's real offset/limit, re-applied here to the rows that
         * matched. When a filter is active {@link Page#from} widens the scan
         * window so the handler feeds us every candidate; without that, a filter
         * could only ever search one page.
         */
        private final int winOffset;
        private final int winLimit;
        /**
         * The caller's requested offset, tracked even when no filter is active so
         * {@link #build()} can say that rows were withheld. Without it a paged
         * reply looks identical to a complete one.
         */
        private final int pageOffset;
        /** True when {@link Page#MAX_LIMIT} cut the requested limit down. */
        private final boolean limitClamped;
        private final StringBuilder sb;
        private int emitted;
        private int matched;
        private boolean limitReached;
        private int total = -1;
        private boolean truncated;
        private boolean jsonFirst = true;

        private Table(Fmt fmt, String[] cols, int expectedRows) {
            this(fmt, cols, expectedRows, null, null, false, MAX_BYTES, 0, Integer.MAX_VALUE, 0, false);
        }

        private Table(Fmt fmt, String[] cols, int expectedRows, int[] keep, Pattern rowFilter,
                      boolean countOnly, int maxBytes, int winOffset, int winLimit,
                      int pageOffset, boolean limitClamped) {
            this.pageOffset = pageOffset;
            this.limitClamped = limitClamped;
            this.fmt = fmt;
            this.cols = cols;
            this.keep = keep;
            this.rowFilter = rowFilter;
            this.countOnly = countOnly;
            this.maxBytes = maxBytes;
            this.winOffset = winOffset;
            this.winLimit = winLimit;
            this.sb = new StringBuilder(Math.min(maxBytes, Math.max(256, expectedRows * 48)));
            header();
        }

        /** Source index of output column {@code i}. */
        private int col(int i) {
            return keep == null ? i : keep[i];
        }

        /** How many columns this table actually emits. */
        private int width() {
            return keep == null ? cols.length : keep.length;
        }

        private void header() {
            if (countOnly) return;
            switch (fmt) {
                case TSV -> {
                    sb.append("# format=tsv; addr=hex; cols=");
                    for (int i = 0; i < width(); i++) {
                        if (i > 0) sb.append(',');
                        sb.append(cols[col(i)]);
                    }
                    sb.append('\n');
                }
                case CSV -> {
                    for (int i = 0; i < width(); i++) {
                        if (i > 0) sb.append(',');
                        sb.append(cols[col(i)]);
                    }
                    sb.append('\n');
                }
                case JSON -> sb.append('[');
                case VERBOSE -> {}
            }
        }

        /**
         * Match against the whole row, not just the projected columns.
         *
         * <p>{@code fields} chooses what is displayed; {@code grep} chooses which
         * rows. Filtering only on the projected columns would make
         * {@code grep=vector fields=addr} silently return nothing, because the
         * name it matches on is not one of the columns being shown.
         */
        private boolean matches(Object[] values) {
            var joined = new StringBuilder(96);
            for (int i = 0; i < values.length; i++) {
                if (i > 0) joined.append('\t');
                joined.append(values[i]);
            }
            return rowFilter.matcher(joined).find();
        }

        public Table row(Object... values) {
            if (truncated) return this;
            if (rowFilter != null && !matches(values)) return this;
            matched++;
            if (countOnly) return this;
            // Page the matches, not the candidates.
            if (matched <= winOffset) return this;
            if (emitted >= winLimit) {
                limitReached = true;
                return this;
            }
            int mark = sb.length();
            switch (fmt) {
                case TSV -> {
                    for (int i = 0; i < width(); i++) {
                        if (i > 0) sb.append('\t');
                        int c = col(i);
                        if (c < values.length) sb.append(cell(String.valueOf(values[c])));
                    }
                    sb.append('\n');
                }
                case CSV -> {
                    for (int i = 0; i < width(); i++) {
                        if (i > 0) sb.append(',');
                        int c = col(i);
                        if (c < values.length) appendCsv(String.valueOf(values[c]));
                    }
                    sb.append('\n');
                }
                case JSON -> {
                    if (!jsonFirst) sb.append(',');
                    jsonFirst = false;
                    sb.append('{');
                    for (int i = 0; i < width(); i++) {
                        int c = col(i);
                        if (c >= values.length) continue;
                        if (i > 0) sb.append(',');
                        sb.append('"').append(cols[c]).append("\":");
                        appendJsonValue(values[c]);
                    }
                    sb.append('}');
                }
                case VERBOSE -> {
                    for (int i = 0; i < width(); i++) {
                        int c = col(i);
                        if (c >= values.length) continue;
                        if (i > 0) sb.append(' ');
                        sb.append(cols[c]).append('=').append(values[c]);
                    }
                    sb.append('\n');
                }
            }
            emitted++;
            if (sb.length() > maxBytes) {
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
            if (fmt != Fmt.JSON) {
                if (rowFilter != null) {
                    // With a filter active, "total" alone is misleading: say how many
                    // rows were scanned and how many actually matched.
                    sb.append("# matched=").append(matched);
                    if (total >= 0) sb.append(" of scanned=").append(total);
                    if (!countOnly && (winOffset > 0 || limitReached)) {
                        sb.append("; showing ").append(winOffset).append("..")
                          .append(winOffset + emitted).append(" of the matches");
                        if (limitReached) {
                            sb.append(" — next: offset=").append(winOffset + emitted);
                        }
                    }
                    sb.append('\n');
                } else if (total >= 0) {
                    sb.append("# total=").append(total).append('\n');
                    // An unfiltered page that stopped short of the total is
                    // indistinguishable from a complete one unless we say so.
                    if (!countOnly && emitted > 0 && pageOffset + emitted < total) {
                        sb.append("# showing ").append(pageOffset).append("..")
                          .append(pageOffset + emitted).append(" of ").append(total)
                          .append(" — next: offset=").append(pageOffset + emitted);
                        if (limitClamped) {
                            sb.append(" (limit clamped to ").append(Page.MAX_LIMIT).append(')');
                        }
                        sb.append('\n');
                    }
                }
                if (countOnly) {
                    sb.append("# count only — drop count=1 to see the rows\n");
                }
                if (keep != null) {
                    sb.append("# fields=");
                    for (int i = 0; i < width(); i++) {
                        if (i > 0) sb.append(',');
                        sb.append(cols[col(i)]);
                    }
                    sb.append(" (of ").append(cols.length).append(" available)\n");
                }
            }
            if (truncated) {
                sb.append("# ...truncated at ").append(maxBytes)
                  .append(" bytes — narrow with fields=, grep=, or a smaller limit\n");
            }
            return sb.toString();
        }
    }

    /**
     * Parses the response-shaping parameters every table endpoint understands.
     *
     * <p>These exist to keep a caller from having to pull a wide table into its
     * context just to read one column of it:
     *
     * <ul>
     *   <li>{@code fields=a,c} — emit only those columns, in that order</li>
     *   <li>{@code grep=regex} — emit only rows matching (case-insensitive)</li>
     *   <li>{@code count=1} — report how many matched and emit no rows</li>
     *   <li>{@code max_bytes=n} — raise or lower the response cap</li>
     * </ul>
     */
    private static Table shaped(Fmt fmt, String[] cols, int expectedRows, Map<String, String> q) {
        if (q == null) return new Table(fmt, cols, expectedRows);
        int reqOffset = Math.max(0, Http.parseIntOrDefault(q.get("offset"), 0));
        int reqLimit = Http.parseIntOrDefault(q.get("limit"), Page.DEFAULT_LIMIT);
        boolean clamped = reqLimit > Page.MAX_LIMIT;
        int winOffset = 0;
        int winLimit = Integer.MAX_VALUE;
        if (Page.hasFilter(q)) {
            // Page.from widened the handler's scan window so we see everything;
            // recover what the caller actually asked for and apply it to the matches.
            winOffset = reqOffset;
            winLimit = reqLimit <= 0 ? Page.DEFAULT_LIMIT : Math.min(reqLimit, Page.MAX_LIMIT);
        }
        return new Table(fmt, cols, expectedRows, parseFields(cols, q.get("fields")),
                parseGrep(q.get("grep")), isTrue(q.get("count")), parseMaxBytes(q.get("max_bytes")),
                winOffset, winLimit, reqOffset, clamped);
    }

    /** Resolve {@code fields=} to column indices; unknown names are ignored. */
    static int[] parseFields(String[] cols, String spec) {
        if (spec == null || spec.isBlank()) return null;
        var picked = new ArrayList<Integer>();
        for (var raw : spec.split(",")) {
            var want = raw.trim();
            if (want.isEmpty()) continue;
            for (int i = 0; i < cols.length; i++) {
                if (cols[i].equalsIgnoreCase(want) && !picked.contains(i)) {
                    picked.add(i);
                    break;
                }
            }
        }
        if (picked.isEmpty()) return null;
        var out = new int[picked.size()];
        for (int i = 0; i < out.length; i++) out[i] = picked.get(i);
        return out;
    }

    /** A malformed regex falls back to a literal match rather than failing the call. */
    static Pattern parseGrep(String spec) {
        if (spec == null || spec.isBlank()) return null;
        try {
            return Pattern.compile(spec, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            return Pattern.compile(Pattern.quote(spec), Pattern.CASE_INSENSITIVE);
        }
    }

    static int parseMaxBytes(String spec) {
        if (spec == null || spec.isBlank()) return MAX_BYTES;
        try {
            return Math.max(1_000, Math.min(Integer.parseInt(spec.trim()), 2_000_000));
        } catch (NumberFormatException e) {
            return MAX_BYTES;
        }
    }

    private static boolean isTrue(String v) {
        if (v == null) return false;
        var s = v.trim().toLowerCase(Locale.ROOT);
        return s.equals("1") || s.equals("true") || s.equals("yes") || s.equals("on");
    }

    public static Table table(Fmt fmt, String[] cols, int expectedRows) {
        return new Table(fmt, cols, expectedRows);
    }

    public static Table table(Map<String, String> q, String[] cols, int expectedRows) {
        return shaped(pickFmt(q), cols, expectedRows, q);
    }

    public static Table table(Page p, Map<String, String> q, String[] cols) {
        return shaped(pickFmt(q), cols, Math.min(p.limit(), 512), q);
    }

    public static String page(Map<String, String> q, Page p, String[] cols, List<Object[]> rows) {
        boolean includeAuto = "1".equals(q.get("include_auto"));
        var t = shaped(pickFmt(q), cols, Math.min(p.limit(), rows.size()), q);
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
