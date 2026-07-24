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
        return new Page(off, lim);
    }

    public String paginate(Stream<String> stream) {
        return stream.skip(Math.max(0, offset))
                     .limit(Math.max(0, limit))
                     .collect(Collectors.joining("\n"));
    }
}
