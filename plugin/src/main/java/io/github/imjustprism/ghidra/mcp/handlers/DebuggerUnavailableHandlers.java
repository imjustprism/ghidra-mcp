package io.github.imjustprism.ghidra.mcp.handlers;

import io.github.imjustprism.ghidra.mcp.http.RouteTable;

public final class DebuggerUnavailableHandlers {

    private static final String UNAVAILABLE =
            "Debugger module unavailable. This Ghidra install doesn't include the "
                    + "Debugger module (Debugger.jar, Debugger-api.jar, "
                    + "Debugger-rmi-trace.jar, Framework-TraceModeling.jar). Install a "
                    + "full Ghidra release, re-run plugin/setup-libs.ps1 against it, "
                    + "rebuild, and run that Ghidra. Then launch a debug session via "
                    + "the Debugger tool before calling these endpoints.";

    private DebuggerUnavailableHandlers() {}

    public static void register(RouteTable routes) {
        for (var path : new String[]{
                "/debugger_status", "/debugger_list_targets", "/debugger_list_modules",
                "/debugger_threads", "/debugger_stack_trace", "/debugger_registers",
                "/debugger_read_memory", "/debugger_list_breakpoints",
                "/debugger_translate_static_to_dynamic",
                "/debugger_translate_dynamic_to_static",
                "/debugger_list_offers", "/list_frozen", "/value_scan", "/scan_results"}) {
            routes.getQuery(path, q -> UNAVAILABLE);
        }
        for (var path : new String[]{
                "/debugger_set_breakpoint", "/debugger_remove_breakpoint",
                "/debugger_continue", "/debugger_step_into", "/debugger_step_over",
                "/debugger_break", "/live_write_memory", "/live_write_register",
                "/debugger_launch", "/freeze_value", "/unfreeze_value", "/next_scan"}) {
            routes.postForm(path, p -> UNAVAILABLE);
        }
    }
}
