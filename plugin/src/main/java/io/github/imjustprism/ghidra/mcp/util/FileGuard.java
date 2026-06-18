package io.github.imjustprism.ghidra.mcp.util;

import ghidra.util.Msg;

import java.io.File;
import java.io.IOException;

public final class FileGuard {

    private static final String OPTION_CATEGORY = "Ghidra MCP HTTP Server";
    private static final String FILE_IO_DIR_OPTION = "File IO Directory";

    private FileGuard() {}

    public static File requireAllowedPath(PluginContext ctx, String path) {
        if (path == null || path.isBlank()) throw new IllegalArgumentException("path is required");
        var allowed = ctx.tool().getOptions(OPTION_CATEGORY).getString(FILE_IO_DIR_OPTION, "");
        if (allowed == null || allowed.isBlank()) {
            throw new IllegalStateException("File I/O is disabled. Set '" + FILE_IO_DIR_OPTION
                    + "' (Edit > Tool Options > " + OPTION_CATEGORY + ") to an allow-listed directory.");
        }
        try {
            var base = new File(allowed).getCanonicalFile();
            if (!base.isDirectory()) {
                throw new IllegalStateException("'" + FILE_IO_DIR_OPTION + "' is not a directory: " + base);
            }
            var target = new File(path).getCanonicalFile();
            for (var f = target.getParentFile(); f != null; f = f.getParentFile()) {
                if (f.equals(base)) {
                    Msg.info(ctx.logOwner(), "MCP file I/O allowed: " + target);
                    return target;
                }
            }
            throw new IllegalArgumentException("path is outside the allowed directory " + base + ": " + target);
        } catch (IOException e) {
            throw new IllegalStateException("path validation failed: " + e.getMessage(), e);
        }
    }
}
