package io.github.imjustprism.ghidra.mcp.http;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public record Page(int offset, int limit) {

    public static final int DEFAULT_LIMIT = 50;

    public static final int MAX_LIMIT = 1000;

    public static Page from(Map<String, String> q) {
        int off = Math.max(0, Http.parseIntOrDefault(q.get("offset"), 0));
        int lim = Http.parseIntOrDefault(q.get("limit"), DEFAULT_LIMIT);
        if (lim <= 0) lim = DEFAULT_LIMIT;
        if (lim > MAX_LIMIT) lim = MAX_LIMIT;
        if (hasFilter(q)) {
            // A row filter has to see every candidate, not just the ones that
            // happen to fall inside the requested page — otherwise grep only
            // searches one page and silently misses the rest. Widen the scan
            // window here; Responses.Table re-applies the caller's real
            // offset/limit to the rows that actually matched.
            return new Page(0, Integer.MAX_VALUE);
        }
        return new Page(off, lim);
    }

    /** True when the request asks the table layer to filter or count rows. */
    public static boolean hasFilter(Map<String, String> q) {
        if (q == null) return false;
        var grep = q.get("grep");
        if (grep != null && !grep.isBlank()) return true;
        var count = q.get("count");
        return count != null && (count.equals("1") || count.equalsIgnoreCase("true")
                || count.equalsIgnoreCase("yes") || count.equalsIgnoreCase("on"));
    }

    public String paginate(Stream<String> stream) {
        return stream.skip(Math.max(0, offset))
                     .limit(Math.max(0, limit))
                     .collect(Collectors.joining("\n"));
    }
}
