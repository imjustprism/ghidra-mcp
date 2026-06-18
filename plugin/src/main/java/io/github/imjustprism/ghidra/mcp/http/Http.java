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

    public static long parseFlexibleLong(String s, long d) {
        if (s == null || s.isBlank()) return d;
        var v = s.trim();
        try {
            return v.startsWith("0x") || v.startsWith("0X")
                    ? Long.parseLong(v.substring(2), 16)
                    : Long.parseLong(v);
        } catch (NumberFormatException e) {
            return d;
        }
    }

    public static boolean parseBool(String s, boolean d) {
        if (s == null || s.isBlank()) return d;
        return switch (s.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "1", "true", "yes", "on" -> true;
            case "0", "false", "no", "off" -> false;
            default -> d;
        };
    }

    public static void sendResponse(HttpExchange ex, int status, String body) throws IOException {
        sendResponse(ex, status, body, "text/plain; charset=utf-8");
    }

    public static void sendResponse(HttpExchange ex, int status, String body, String contentType)
            throws IOException {
        var bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
