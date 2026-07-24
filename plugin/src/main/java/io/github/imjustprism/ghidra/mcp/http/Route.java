package io.github.imjustprism.ghidra.mcp.http;

import com.sun.net.httpserver.HttpExchange;

import java.util.Map;

public final class Route {

    private Route() {}

    @FunctionalInterface public interface PageFn { String apply(Page p, Map<String, String> q); }

    @FunctionalInterface public interface QueryFn { String apply(Map<String, String> q); }

    @FunctionalInterface public interface RawFn { String apply(String body); }

    @FunctionalInterface public interface ExchangeHandler {
        String handle(HttpExchange ex) throws Exception;
    }
}
