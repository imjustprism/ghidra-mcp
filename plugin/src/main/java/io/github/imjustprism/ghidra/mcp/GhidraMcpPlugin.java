package io.github.imjustprism.ghidra.mcp;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.util.Swing;
import io.github.imjustprism.ghidra.mcp.handlers.AnalysisHandlers;
import io.github.imjustprism.ghidra.mcp.handlers.BytesHandlers;
import io.github.imjustprism.ghidra.mcp.handlers.DebuggerHandlers;
import io.github.imjustprism.ghidra.mcp.handlers.DebuggerUnavailableHandlers;
import io.github.imjustprism.ghidra.mcp.handlers.DecompileHandlers;
import io.github.imjustprism.ghidra.mcp.handlers.EditHandlers;
import io.github.imjustprism.ghidra.mcp.handlers.FunctionHandlers;
import io.github.imjustprism.ghidra.mcp.handlers.ListingHandlers;
import io.github.imjustprism.ghidra.mcp.handlers.RecoveryHandlers;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;

import java.io.IOException;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Ghidra MCP HTTP bridge",
    description = "Embedded HTTP server exposing Ghidra program state to the ghidra-mcp MCP bridge. Reversing-focused endpoints for decompilation, patching, call graphs, byte search, and anti-debug triage."
)
public final class GhidraMcpPlugin extends Plugin {

    private static final String OPTION_CATEGORY = "Ghidra MCP HTTP Server";
    private static final String PORT_OPTION = "Server Port";
    private static final String BIND_OPTION = "Bind Address";
    private static final String TOKEN_OPTION = "Auth Token";
    private static final int DEFAULT_PORT = 8080;
    private static final String DEFAULT_BIND = "127.0.0.1";

    private static final java.util.List<String> DEBUGGER_SERVICE_PLUGINS = java.util.List.of(
        "ghidra.app.plugin.core.debug.service.progress.ProgressServicePlugin",
        "ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin",
        "ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin",
        "ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin",
        "ghidra.app.plugin.core.debug.service.platform.DebuggerPlatformServicePlugin",
        "ghidra.app.plugin.core.debug.service.target.DebuggerTargetServicePlugin",
        "ghidra.app.plugin.core.debug.service.breakpoint.DebuggerLogicalBreakpointServicePlugin",
        "ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin",
        "ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin",
        "ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin"
    );

    private final RouteTable routes = new RouteTable(this);
    private DebuggerHandlers debuggerHandlers;

    public GhidraMcpPlugin(PluginTool tool) {
        super(tool);
        var options = tool.getOptions(OPTION_CATEGORY);
        options.registerOption(PORT_OPTION, DEFAULT_PORT, null,
            "HTTP port (requires Ghidra restart to take effect).");
        options.registerOption(BIND_OPTION, DEFAULT_BIND, null,
            "Interface to bind to. Defaults to loopback. Never expose to untrusted networks.");
        options.registerOption(TOKEN_OPTION, "", null,
            "If set, every request must carry 'Authorization: Bearer <token>'. "
                + "Pass the same value to the bridge via GHIDRA_TOKEN.");
        try {
            startServer();
        } catch (IOException e) {
            Msg.error(this, "Failed to start Ghidra MCP HTTP server", e);
        }
    }

    @Override
    public void dispose() {
        if (debuggerHandlers != null) debuggerHandlers.close();
        routes.stop();
        super.dispose();
    }

    private void startServer() throws IOException {
        var options = tool.getOptions(OPTION_CATEGORY);
        int port = options.getInt(PORT_OPTION, DEFAULT_PORT);
        String bind = options.getString(BIND_OPTION, DEFAULT_BIND);

        routes.setAuthToken(options.getString(TOKEN_OPTION, ""));
        routes.bind(bind, port);

        var ctx = new PluginContext(tool, this);
        var listing = new ListingHandlers(ctx);
        var functions = new FunctionHandlers(ctx);
        var decompile = new DecompileHandlers(ctx);
        var bytes = new BytesHandlers(ctx);
        var edits = new EditHandlers(ctx);
        var analysis = new AnalysisHandlers(ctx);
        var recovery = new RecoveryHandlers(ctx);

        listing.register(routes);
        functions.register(routes);
        decompile.register(routes);
        bytes.register(routes);
        edits.register(routes);
        analysis.register(routes);
        recovery.register(routes);

        try {
            debuggerHandlers = new DebuggerHandlers(ctx);
            debuggerHandlers.register(routes);
            Swing.runLater(this::ensureDebuggerServices);
        } catch (Throwable t) {
            Msg.warn(this, "Debugger module unavailable; registering stub debugger endpoints", t);
            DebuggerUnavailableHandlers.register(routes);
        }

        routes.start(bind, port);
    }

    private void ensureDebuggerServices() {
        try {
            tool.addPlugins(DEBUGGER_SERVICE_PLUGINS);
        } catch (Throwable t) {
            Msg.warn(this, "Could not auto-load debugger service plugins into this tool", t);
        }
    }
}
