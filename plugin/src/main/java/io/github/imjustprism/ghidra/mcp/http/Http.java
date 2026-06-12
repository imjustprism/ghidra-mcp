package io.github.imjustprism.ghidra.mcp.http;

import com.sun.net.httpserver.HttpExchange;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public final class Http {

    private Http() {}

    public static Map<String, String> parseQuery(HttpExchange ex) {
        return parsePairs(ex.getRequestURI().getQuery());
    }

    public static Map<String, String> parseForm(HttpExchange ex) throws IOException {
        return parsePairs(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
    }

    public static Map<String, String> parsePairs(String raw) {
        if (raw == null || raw.isEmpty()) return Map.of();
        var out = new HashMap<String, String>();
        for (var pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) continue;
            try {
                var k = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
                var v = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                out.put(k, v);
            } catch (IllegalArgumentException e) {
                Msg.trace(Http.class, "malformed url pair", e);
            }
        }
        return out;
    }

    public static int parseIntOrDefault(String s, int d) {
        if (s == null) return d;
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return d;
        }
    }

    public static void sendResponse(HttpExchange ex, int status, String body) throws IOException {
        var bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
