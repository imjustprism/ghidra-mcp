package io.github.imjustprism.ghidra.mcp.util;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.function.Supplier;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public final class Programs {

    private Programs() {}

    public static Stream<Function> functions(Program program) {
        return StreamSupport.stream(program.getFunctionManager().getFunctions(true).spliterator(), false);
    }

    public static Stream<Symbol> symbols(Program program) {
        return StreamSupport.stream(
                ((Iterable<Symbol>) () -> program.getSymbolTable().getAllSymbols(true)).spliterator(),
                false);
    }

    public static Function findFunctionByName(Program program, String name) {
        for (var f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name)) return f;
        }
        return null;
    }

    public static boolean runOnSwing(Object logOwner, Supplier<Boolean> action) {
        if (SwingUtilities.isEventDispatchThread()) return action.get();
        var result = new boolean[1];
        try {
            SwingUtilities.invokeAndWait(() -> result[0] = action.get());
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(logOwner, "Swing action failed", e);
            Thread.currentThread().interrupt();
            return false;
        }
        return result[0];
    }

    public static boolean runOnSwingTx(Object logOwner, Program program, String txName, Supplier<Boolean> body) {
        return runOnSwing(logOwner, () -> {
            int tx = program.startTransaction(txName);
            boolean ok = false;
            try {
                ok = body.get();
                return ok;
            } finally {
                program.endTransaction(tx, ok);
            }
        });
    }
}
