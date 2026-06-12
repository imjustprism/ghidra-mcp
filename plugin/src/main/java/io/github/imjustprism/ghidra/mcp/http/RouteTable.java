package io.github.imjustprism.ghidra.mcp.http;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import ghidra.util.Msg;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class RouteTable {

    private final Object owner;
    private HttpServer server;
    private ExecutorService executor;

    public RouteTable(Object owner) {
        this.owner = owner;
    }

    public void bind(String bind, int port) throws IOException {
        stop();
        server = HttpServer.create(new InetSocketAddress(bind, port), 64);
    }

    public void start(String bind, int port) {
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
            return fn.apply(Page.from(q), q);
        }));
    }

    public void getQuery(String path, Route.QueryFn fn) {
        server.createContext(path, wrap(ex -> fn.apply(Http.parseQuery(ex))));
    }

    public void postForm(String path, Route.QueryFn fn) {
        server.createContext(path, wrap(ex -> fn.apply(Http.parseForm(ex))));
    }

    public void postRaw(String path, Route.RawFn fn) {
        server.createContext(path, wrap(ex -> fn.apply(
                new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8))));
    }

    private HttpHandler wrap(Route.ExchangeHandler h) {
        return ex -> {
            try {
                var body = h.handle(ex);
                Http.sendResponse(ex, 200, body == null ? "" : body);
            } catch (IllegalArgumentException iae) {
                Http.sendResponse(ex, 400, "Bad request: " + iae.getMessage());
            } catch (Exception e) {
                Msg.error(owner, "Handler failed for " + ex.getRequestURI(), e);
                Http.sendResponse(ex, 500, "Internal error");
            }
        };
    }
}
