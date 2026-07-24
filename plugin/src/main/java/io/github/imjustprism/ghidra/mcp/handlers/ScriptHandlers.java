package io.github.imjustprism.ghidra.mcp.handlers;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.GhidraSourceBundle;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Programs;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ScriptHandlers {

    private static final String WRAP_IMPORTS = String.join("\n",
            "import ghidra.app.script.GhidraScript;",
            "import ghidra.program.model.address.*;",
            "import ghidra.program.model.listing.*;",
            "import ghidra.program.model.symbol.*;",
            "import ghidra.program.model.data.*;",
            "import ghidra.program.model.mem.*;",
            "import ghidra.program.model.scalar.*;",
            "import ghidra.program.model.block.*;",
            "import ghidra.program.model.pcode.*;",
            "import ghidra.app.decompiler.*;",
            "import java.util.*;",
            "import io.github.imjustprism.ghidra.mcp.util.Live;",
            "import static io.github.imjustprism.ghidra.mcp.util.Live.*;");

    private static final Pattern CLASS_DECL = Pattern.compile("class\\s+(\\w+)");
    private static final int MAX_OUTPUT_CHARS = 200_000;

    private final PluginContext ctx;
    private final AtomicLong seq = new AtomicLong();

    public ScriptHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    public void register(RouteTable routes) {
        routes.postForm("/ghidra_eval",
                p -> eval(p.get("lang"), p.get("code"), p.get("commit")));
    }

    private String eval(String lang, String code, String commitStr) {
        if (scriptingDisabled()) {
            throw new IllegalStateException("Scripting is disabled "
                    + "(GHIDRA_MCP_SCRIPTING=off). Remove the env var to enable arbitrary code execution.");
        }
        if (code == null || code.isBlank()) throw new IllegalArgumentException("code is required");
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        boolean commit = commitStr == null || !commitStr.equalsIgnoreCase("false") && !"0".equals(commitStr);
        var language = lang == null || lang.isBlank() ? "java" : lang.trim().toLowerCase();

        var prepared = prepareSource(language, code);
        Msg.warn(this, "ghidra_eval running " + language + " script " + prepared.className
                + " (" + code.length() + " chars, commit=" + commit + ")");

        var output = new StringWriter();
        var writer = new PrintWriter(output);
        var sourceFile = writeSource(prepared);
        var failure = new String[1];
        try {
            Programs.runOnSwing(ctx.logOwner(), () -> {
                runScript(sourceFile, program, writer, commit, failure);
                return true;
            });
        } finally {
            sourceFile.delete();
        }
        writer.flush();
        return formatResult(prepared.className, language, commit, failure[0], output.toString());
    }

    private void runScript(File sourceFile, ghidra.program.model.listing.Program program,
            PrintWriter writer, boolean commit, String[] failure) {
        var bundleHost = GhidraScriptUtil.acquireBundleHostReference();
        try {
            var dir = new ResourceFile(sourceFile.getParentFile());
            if (!(bundleHost.getExistingGhidraBundle(dir) instanceof GhidraSourceBundle)) {
                bundleHost.add(dir, true, false);
            }
            bundleHost.enable(dir);
            var src = new ResourceFile(sourceFile);
            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(src);
            if (provider == null) {
                failure[0] = "No script provider for this language. Java is always available; "
                        + "Python needs PyGhidra/Ghidrathon installed in this Ghidra.";
                return;
            }
            GhidraScript script;
            try {
                script = provider.getScriptInstance(src, writer);
            } catch (Throwable e) {
                failure[0] = "compilation failed — see compiler errors in the output below. "
                        + "Note: a bare snippet is wrapped in a class body, so a reported line N is "
                        + "roughly your line N-13 (use a full 'class X extends GhidraScript' to avoid the offset).";
                return;
            }
            var tool = ctx.tool();
            var state = new GhidraState(tool, tool.getProject(), program, null, null, null);
            int tx = program.startTransaction("ghidra_eval");
            boolean ok = false;
            try {
                script.execute(state, TaskMonitor.DUMMY, writer);
                ok = true;
            } catch (Throwable e) {
                failure[0] = describe(e);
            } finally {
                program.endTransaction(tx, ok && commit);
            }
        } catch (Throwable e) {
            failure[0] = describe(e);
        } finally {
            GhidraScriptUtil.releaseBundleHostReference();
        }
    }

    private record Prepared(String className, String source, String extension) {}

    private Prepared prepareSource(String language, String code) {
        if (language.equals("python") || language.equals("py")) {
            return new Prepared("mcp_eval_" + seq.incrementAndGet(), code, ".py");
        }
        if (!language.equals("java")) {
            throw new IllegalArgumentException("lang must be 'java' or 'python'");
        }
        var className = "McpEval_" + seq.incrementAndGet();
        if (code.contains("extends GhidraScript")) {
            var m = CLASS_DECL.matcher(code);
            if (m.find()) {
                var renamed = code.replaceFirst("class\\s+" + Pattern.quote(m.group(1)),
                        "class " + className);
                return new Prepared(className, renamed, ".java");
            }
        }
        var imports = new StringBuilder();
        var body = new StringBuilder();
        for (var line : code.split("\n", -1)) {
            if (line.strip().startsWith("import ")) imports.append(line.strip()).append('\n');
            else body.append(line).append('\n');
        }
        var source = WRAP_IMPORTS + "\n" + imports + "public class " + className
                + " extends GhidraScript {\n    @Override public void run() throws Exception {\n"
                + body + "\n    }\n}\n";
        return new Prepared(className, source, ".java");
    }

    private File writeSource(Prepared prepared) {
        var dir = GhidraScriptUtil.getUserScriptDirectory().getFile(false);
        var file = new File(dir, prepared.className + prepared.extension);
        try {
            java.nio.file.Files.createDirectories(dir.toPath());
            java.nio.file.Files.writeString(file.toPath(), prepared.source);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to stage script: " + e.getMessage());
        }
        return file;
    }

    private static String formatResult(String className, String language, boolean commit,
            String failure, String output) {
        var sb = new StringBuilder();
        sb.append("# ").append(language).append(" eval ").append(className)
                .append(failure == null ? " OK" : " FAILED")
                .append(commit ? "" : " (commit=false, rolled back)").append('\n');
        if (failure != null) sb.append("ERROR: ").append(failure).append('\n');
        var trimmed = output.length() > MAX_OUTPUT_CHARS
                ? output.substring(0, MAX_OUTPUT_CHARS) + "\n...[truncated]" : output;
        if (!trimmed.isBlank()) sb.append("--- output ---\n").append(trimmed);
        else if (failure == null) sb.append("(no output; use println(...) to print)");
        return sb.toString();
    }

    private static String describe(Throwable e) {
        var sb = new StringBuilder();
        for (Throwable c = e; c != null && sb.length() < 2000; c = c.getCause()) {
            sb.append(c.getClass().getSimpleName());
            if (c.getMessage() != null) sb.append(": ").append(c.getMessage());
            sb.append(" | ");
            if (c == c.getCause()) break;
        }
        return sb.toString();
    }

    private static boolean scriptingDisabled() {
        var v = System.getenv("GHIDRA_MCP_SCRIPTING");
        if (v == null) return false;
        var t = v.trim().toLowerCase();
        return t.equals("off") || t.equals("0") || t.equals("false") || t.equals("no");
    }
}
