package io.github.imjustprism.ghidra.mcp.http;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import ghidra.util.Msg;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

public final class RouteTable {

    private static final int MAX_CONCURRENT = Math.max(4, Runtime.getRuntime().availableProcessors());

    private final Object owner;
    private volatile Semaphore concurrency = new Semaphore(MAX_CONCURRENT, true);
    private HttpServer server;
    private ExecutorService executor;
    private volatile String authToken = "";

    public RouteTable(Object owner) {
        this.owner = owner;
    }

    public void setAuthToken(String token) {
        authToken = token == null ? "" : token.trim();
    }

    public void bind(String bind, int port) throws IOException {
        stop();
        server = HttpServer.create(new InetSocketAddress(bind, port), 64);
    }

    public void start(String bind, int port) {
        concurrency = new Semaphore(MAX_CONCURRENT, true);
        executor = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual().name("ghidra-mcp-http-", 0).factory());
        server.setExecutor(executor);

        var starter = new Thread(() -> {
            try {
                server.start();
                Msg.info(owner, "Ghidra MCP HTTP server listening on " + bind + ":" + port);
            } catch (Exception e) {
                Msg.error(owner, "HTTP start failed on " + bind + ":" + port, e);
                server = null;
            }
        }, "ghidra-mcp-http-starter");
        starter.setDaemon(true);
        starter.start();
    }

    public void stop() {
        if (server != null) {
            server.stop(1);
            server = null;
        }
        if (executor != null) {
            executor.shutdown();
            executor = null;
        }
    }

    public void getPage(String path, Route.PageFn fn) {
        server.createContext(path, wrap(ex -> {
            var q = Http.parseQuery(ex);
            PluginContext.setProgramOverride(q.get("program"));
            try {
                return fn.apply(Page.from(q), q);
            } finally {
                PluginContext.clearProgramOverride();
            }
        }));
    }

    public void getQuery(String path, Route.QueryFn fn) {
        server.createContext(path, wrap(ex -> {
            var q = Http.parseQuery(ex);
            PluginContext.setProgramOverride(q.get("program"));
            try {
                return fn.apply(q);
            } finally {
                PluginContext.clearProgramOverride();
            }
        }));
    }

    public void getHtml(String path, Route.QueryFn fn) {
        server.createContext(path, wrap(ex -> {
            var q = Http.parseQuery(ex);
            PluginContext.setProgramOverride(q.get("program"));
            try {
                return fn.apply(q);
            } finally {
                PluginContext.clearProgramOverride();
            }
        }, "text/html; charset=utf-8"));
    }

    public void postForm(String path, Route.QueryFn fn) {
        server.createContext(path, wrap(ex -> {
            var form = Http.parseForm(ex);
            PluginContext.setProgramOverride(form.get("program"));
            try {
                return fn.apply(form);
            } finally {
                PluginContext.clearProgramOverride();
            }
        }));
    }

    public void postRaw(String path, Route.RawFn fn) {
        server.createContext(path, wrap(ex -> fn.apply(
                new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8))));
    }

    private HttpHandler wrap(Route.ExchangeHandler h) {
        return wrap(h, "text/plain; charset=utf-8");
    }

    private HttpHandler wrap(Route.ExchangeHandler h, String contentType) {
        return ex -> {
            if (ex.getRequestHeaders().getFirst("Origin") != null) {
                Http.sendResponse(ex, 403, "Browser origins are not allowed");
                return;
            }
            if (!authToken.isEmpty()) {
                var auth = ex.getRequestHeaders().getFirst("Authorization");
                if (!("Bearer " + authToken).equals(auth)) {
                    Http.sendResponse(ex, 401, "Missing or invalid Authorization bearer token");
                    return;
                }
            }
            var sem = concurrency;
            try {
                sem.acquire();
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                Http.sendResponse(ex, 503, "Server unavailable");
                return;
            }
            try {
                var body = h.handle(ex);
                Http.sendResponse(ex, 200, body == null ? "" : body, contentType);
            } catch (IllegalArgumentException iae) {
                Http.sendResponse(ex, 400, "Bad request: " + iae.getMessage());
            } catch (Exception e) {
                Msg.error(owner, "Handler failed for " + ex.getRequestURI(), e);
                var msg = e.getMessage();
                Http.sendResponse(ex, 500,
                        msg == null || msg.isBlank() ? "Internal error" : msg);
            } finally {
                sem.release();
            }
        };
    }
}
