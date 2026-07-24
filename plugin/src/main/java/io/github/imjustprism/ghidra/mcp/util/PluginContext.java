package io.github.imjustprism.ghidra.mcp.util;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

public final class PluginContext {

    private static final ThreadLocal<String> PROGRAM_OVERRIDE = new ThreadLocal<>();

    private final PluginTool tool;
    private final Object logOwner;

    public PluginContext(PluginTool tool, Object logOwner) {
        this.tool = tool;
        this.logOwner = logOwner;
    }

    public static void setProgramOverride(String name) {
        if (name != null && !name.isBlank()) PROGRAM_OVERRIDE.set(name.trim());
    }

    public static void clearProgramOverride() {
        PROGRAM_OVERRIDE.remove();
    }

    public PluginTool tool() {
        return tool;
    }

    public Object logOwner() {
        return logOwner;
    }

    public Program currentProgram() {
        var pm = tool.getService(ProgramManager.class);
        if (pm == null) return null;
        var override = PROGRAM_OVERRIDE.get();
        if (override != null) {
            for (var p : pm.getAllOpenPrograms()) {
                if (p.getName().equals(override) || override.equals(p.getExecutableSHA256())) return p;
            }
            throw new IllegalArgumentException("program not open: " + override
                    + " (use list_open_programs to see open programs)");
        }
        return pm.getCurrentProgram();
    }

    public <T> T service(Class<T> cls) {
        return tool.getService(cls);
    }

    public String withProgram(Function<Program, String> fn) {
        var p = currentProgram();
        if (p == null) throw new IllegalArgumentException("No program loaded");
        return fn.apply(p);
    }

    public String requireProgram(Supplier<String> body) {
        if (currentProgram() == null) throw new IllegalArgumentException("No program loaded");
        return body.get();
    }

    public String withAddress(String addrStr, BiFunction<Program, Address, String> fn) {
        if (addrStr == null || addrStr.isBlank()) throw new IllegalArgumentException("address is required");
        return withProgram(program -> {
            var a = Addresses.resolve(program, addrStr);
            if (a == null) throw new IllegalArgumentException("invalid address: " + addrStr);
            return fn.apply(program, a);
        });
    }

    public boolean runOnSwing(Supplier<Boolean> action) {
        return Programs.runOnSwing(logOwner, action);
    }

    public boolean runOnSwingTx(Program program, String txName, Supplier<Boolean> body) {
        return Programs.runOnSwingTx(logOwner, program, txName, body);
    }
}
