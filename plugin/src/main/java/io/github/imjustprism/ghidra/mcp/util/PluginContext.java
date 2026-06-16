package io.github.imjustprism.ghidra.mcp.util;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;

public final class PluginContext {

    private final PluginTool tool;
    private final Object logOwner;

    public PluginContext(PluginTool tool, Object logOwner) {
        this.tool = tool;
        this.logOwner = logOwner;
    }

    public PluginTool tool() {
        return tool;
    }

    public Object logOwner() {
        return logOwner;
    }

    public Program currentProgram() {
        var pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
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
            Address a;
            try {
                a = program.getAddressFactory().getAddress(addrStr);
            } catch (Exception e) {
                throw new IllegalArgumentException("invalid address: " + addrStr);
            }
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
