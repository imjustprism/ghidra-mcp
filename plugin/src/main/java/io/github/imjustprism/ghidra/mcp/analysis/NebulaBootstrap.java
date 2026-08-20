package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runs the whole Nebula3/DRO symbol-recovery sequence in one call.
 *
 * <p>{@code nebula_engine_survey} prints a recommended chain — seed helpers,
 * name from signature strings, fill in from n_assert decompiles, name singleton
 * instances, derive TLS singletons — and until now the caller had to drive all
 * five tools by hand with the right flags and page sizes. On a fresh
 * dro_client that is five round trips before any naming happens, and the
 * signature step defaults to {@code max=500} against ~20k candidates.
 *
 * <p>The chain takes minutes on a real client (and far longer with the
 * decompile fill-in), which is longer than an MCP client will hold a tool call
 * open. So it runs as a background job in the style of {@code emu_start}: the
 * call returns a job id, and {@code op=status} / {@code op=result} follow it.
 * Short runs still complete in one call because {@code start} waits up to
 * {@code wait} seconds before handing back a job id.
 */
public final class NebulaBootstrap {

    /** High enough to cover every signature-string candidate on dro_client (~20k). */
    public static final int DEFAULT_SIG_MAX = 50_000;
    public static final int DEFAULT_DECOMPILE_MAX = 2_000;
    public static final int DEFAULT_INSTANCE_MAX = 2_000;
    public static final int DEFAULT_TLS_MAX = 120;
    /** Long enough for a small binary to finish inline, short enough for any client. */
    public static final int DEFAULT_WAIT_SECONDS = 25;

    private static final int MAX_RETAINED_JOBS = 8;
    private static final Map<String, Job> JOBS = new ConcurrentHashMap<>();
    private static final AtomicLong SEQUENCE = new AtomicLong();

    private NebulaBootstrap() {}

    /** One step's outcome. A failed step records why and the run continues. */
    private record Step(String name, String status, int named, long millis, String detail) {}

    /** A single background run. Fields written by the worker, read by pollers. */
    private static final class Job {
        final String id;
        final boolean apply;
        final boolean decompile;
        final boolean verbose;
        final long startedAt = System.currentTimeMillis();
        final List<Step> steps = Collections.synchronizedList(new ArrayList<>());
        final Map<String, String> outputs =
                Collections.synchronizedMap(new LinkedHashMap<String, String>());
        final CountDownLatch finished = new CountDownLatch(1);
        volatile String current = "starting";
        volatile long finishedAt;
        volatile String report;
        volatile String error;
        /** Cooperative: honoured between steps, since the steps themselves are atomic. */
        volatile boolean cancelled;

        Job(String id, boolean apply, boolean decompile, boolean verbose) {
            this.id = id;
            this.apply = apply;
            this.decompile = decompile;
            this.verbose = verbose;
        }

        boolean done() {
            return finishedAt != 0;
        }

        long elapsedMs() {
            return (done() ? finishedAt : System.currentTimeMillis()) - startedAt;
        }
    }

    // -----------------------------------------------------------------------
    // entry point
    // -----------------------------------------------------------------------

    public static String dispatch(PluginContext ctx, Map<String, String> q) {
        var op = q.getOrDefault("op", "start");
        op = op == null || op.isBlank() ? "start" : op.trim().toLowerCase(Locale.ROOT);
        return switch (op) {
            case "start", "run" -> start(ctx, q);
            case "status", "poll" -> status(jobOf(q), false);
            case "result", "report" -> status(jobOf(q), true);
            case "list", "jobs" -> list();
            case "cancel", "stop" -> cancel(jobOf(q));
            default -> "# unknown op " + op + "; use start, status, result, cancel, or list\n";
        };
    }

    private static Job jobOf(Map<String, String> q) {
        var id = q.get("job");
        if (id == null || id.isBlank()) {
            // With a single run in flight, not having to name it is friendlier.
            var only = JOBS.values().stream()
                    .max((a, b) -> Long.compare(a.startedAt, b.startedAt)).orElse(null);
            if (only == null) {
                throw new IllegalArgumentException(
                        "no bootstrap jobs yet — call nebula_bootstrap with op=start first");
            }
            return only;
        }
        var job = JOBS.get(id.trim());
        if (job == null) {
            throw new IllegalArgumentException("unknown job id " + id
                    + " (op=list shows the ones still retained)");
        }
        return job;
    }

    private static String start(PluginContext ctx, Map<String, String> q) {
        boolean apply = parseBool(q.get("apply"));
        boolean decompile = parseBool(q.get("decompile"));
        boolean verbose = parseBool(q.get("verbose"));
        int sigMax = parseInt(q.get("sig_max"), DEFAULT_SIG_MAX);
        int decompileMax = parseInt(q.get("decompile_max"), DEFAULT_DECOMPILE_MAX);
        int instanceMax = parseInt(q.get("instance_max"), DEFAULT_INSTANCE_MAX);
        int tlsMax = parseInt(q.get("tls_max"), DEFAULT_TLS_MAX);
        int wait = Math.max(0, Math.min(parseInt(q.get("wait"), DEFAULT_WAIT_SECONDS), 600));

        // The route sets the program override on the request thread only, so the
        // worker has to re-apply it or it would silently run against whichever
        // program happens to be active.
        var programOverride = q.get("program");
        var args = new HashMap<>(q);

        var id = "nb" + SEQUENCE.incrementAndGet();
        var job = new Job(id, apply, decompile, verbose);
        JOBS.put(id, job);
        prune();

        var worker = new Thread(() -> {
            try {
                PluginContext.setProgramOverride(programOverride);
                job.report = execute(ctx, job, sigMax, decompileMax, instanceMax, tlsMax, args);
            } catch (Exception | LinkageError e) {
                job.error = e.getClass().getSimpleName() + ": " + e.getMessage();
            } finally {
                PluginContext.clearProgramOverride();
                job.current = "done";
                job.finishedAt = System.currentTimeMillis();
                job.finished.countDown();
            }
        }, "nebula-bootstrap-" + id);
        worker.setDaemon(true);
        worker.start();

        if (wait > 0) {
            try {
                job.finished.await(wait, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (job.done()) return status(job, true);

        var sb = new StringBuilder(512);
        sb.append("# nebula_bootstrap started job=").append(id)
          .append(" apply=").append(apply).append(" decompile=").append(decompile).append('\n');
        sb.append("# still running after ").append(wait).append("s — this is normal on a full "
                + "client (the signature pass walks ~20k candidates)\n");
        sb.append("# poll: nebula_bootstrap op=status job=").append(id)
          .append("   final report: nebula_bootstrap op=result job=").append(id).append('\n');
        appendProgress(sb, job);
        return sb.toString();
    }

    private static void prune() {
        if (JOBS.size() <= MAX_RETAINED_JOBS) return;
        JOBS.values().stream()
            .filter(Job::done)
            .sorted((a, b) -> Long.compare(a.startedAt, b.startedAt))
            .limit(Math.max(0, JOBS.size() - MAX_RETAINED_JOBS))
            .forEach(j -> JOBS.remove(j.id));
    }

    private static String status(Job job, boolean wantReport) {
        if (job.done()) {
            if (job.error != null) {
                return "# nebula_bootstrap job=" + job.id + " FAILED after "
                        + job.elapsedMs() + "ms\n# " + job.error + '\n';
            }
            if (wantReport && job.report != null) return job.report;
        }
        var sb = new StringBuilder(512);
        sb.append("# nebula_bootstrap job=").append(job.id)
          .append(job.done() ? " done" : " running")
          .append(" apply=").append(job.apply)
          .append(" elapsed=").append(job.elapsedMs()).append("ms\n");
        if (!job.done()) {
            sb.append("# current step: ").append(job.current).append('\n');
        }
        appendProgress(sb, job);
        if (!job.done()) {
            sb.append("# poll again with op=status job=").append(job.id).append('\n');
        }
        return sb.toString();
    }

    private static void appendProgress(StringBuilder sb, Job job) {
        sb.append("# format=tsv; addr=hex; cols=step,status,rows,ms,detail\n");
        synchronized (job.steps) {
            for (var s : job.steps) {
                sb.append(s.name()).append('\t').append(s.status()).append('\t')
                  .append(s.named()).append('\t').append(s.millis()).append('\t')
                  .append(s.detail() == null ? "" : s.detail().replace('\t', ' ')).append('\n');
            }
            if (job.steps.isEmpty()) sb.append("# no step has finished yet\n");
        }
    }

    /**
     * Ask a running job to stop.
     *
     * <p>Cooperative and coarse: the underlying naming tools are single atomic
     * calls with no cancellation hook, so the flag is honoured <em>between</em>
     * steps. A long step already in flight runs to completion.
     */
    private static String cancel(Job job) {
        if (job.done()) {
            return "# job " + job.id + " already finished — nothing to cancel\n";
        }
        job.cancelled = true;
        return "# job " + job.id + " cancelled; the step in flight (" + job.current
                + ") finishes first, then the run stops\n";
    }

    private static String list() {
        var sb = new StringBuilder(256);
        sb.append("# format=tsv; addr=hex; cols=job,state,apply,decompile,steps,ms\n");
        JOBS.values().stream()
            .sorted((a, b) -> Long.compare(a.startedAt, b.startedAt))
            .forEach(j -> sb.append(j.id).append('\t')
                    .append(j.error != null ? "failed" : j.done() ? "done" : "running").append('\t')
                    .append(j.apply).append('\t').append(j.decompile).append('\t')
                    .append(j.steps.size()).append('\t').append(j.elapsedMs()).append('\n'));
        if (JOBS.isEmpty()) sb.append("# no jobs\n");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // the chain
    // -----------------------------------------------------------------------

    private static String execute(PluginContext ctx, Job job, int sigMax, int decompileMax,
                                  int instanceMax, int tlsMax, Map<String, String> q) {
        boolean apply = job.apply;
        var before = surveyCounts(ctx, q);

        // The helpers must be named first: every later step scores candidates by
        // their calls into n_assert/n_error/n_warning.
        step(job, "seed_helpers", () -> NebulaAssertNamer.seedHelpers(ctx, apply, q));

        step(job, "name_from_signatures", () -> NebulaAssertNamer.nameFromSignatures(
                ctx, null, apply, positive(sigMax, DEFAULT_SIG_MAX), q));

        if (job.decompile) {
            step(job, "name_from_n_assert", () -> NebulaAssertNamer.name(
                    ctx, null, apply, positive(decompileMax, DEFAULT_DECOMPILE_MAX),
                    "decompile", q));
        } else {
            job.steps.add(new Step("name_from_n_assert", "skipped", 0, 0,
                    "pass decompile=true to run it (slow: decompiles assert callers)"));
        }

        step(job, "name_nebula_instances", () -> NebulaSingletons.nameInstances(
                ctx, apply, positive(instanceMax, DEFAULT_INSTANCE_MAX), q));

        step(job, "derive_tls_singletons", () -> TlsSingletons.derive(
                ctx, null, positive(tlsMax, DEFAULT_TLS_MAX), apply,
                new Page(0, Page.MAX_LIMIT), q));

        job.current = "survey";
        var after = surveyCounts(ctx, q);
        return report(job, before, after);
    }

    private static int positive(int value, int fallback) {
        return value > 0 ? value : fallback;
    }

    private interface StepBody {
        String get() throws Exception;
    }

    private static void step(Job job, String name, StepBody body) {
        if (job.cancelled) {
            job.steps.add(new Step(name, "cancelled", 0, 0, "run was cancelled before this step"));
            return;
        }
        job.current = name;
        long t0 = System.nanoTime();
        try {
            var out = body.get();
            job.outputs.put(name, out);
            job.steps.add(new Step(name, "ok", countApplied(out), elapsed(t0), headline(out)));
        } catch (Exception | LinkageError e) {
            // One broken step must not cost the caller the other four.
            job.steps.add(new Step(name, "failed", 0, elapsed(t0),
                    e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage())));
        }
    }

    private static long elapsed(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }

    /**
     * Counts rows the underlying tools mark as applied ({@code ok}) or, in a dry
     * run, as proposed ({@code preview}) — the same convention they use among
     * themselves.
     */
    private static int countApplied(String report) {
        if (report == null) return 0;
        int n = 0;
        for (var line : report.split("\n")) {
            if (line.endsWith("\tok") || line.endsWith("\tpreview")) n++;
        }
        // Several steps cap their dry-run preview (name_from_signatures shows 500
        // of ~19k) but state the real figure in their header. Counting only the
        // printed rows would badly understate what an apply run would do.
        int reported = reportedCount(report);
        return Math.max(n, reported);
    }

    private static final java.util.regex.Pattern REPORTED = java.util.regex.Pattern.compile(
            "(\\d+)\\s+(?:rename|name|symbol|instance)", java.util.regex.Pattern.CASE_INSENSITIVE);

    /** The "N rename(s)" figure a step prints in its own header, if it has one. */
    private static int reportedCount(String report) {
        int best = 0;
        for (var line : report.split("\n")) {
            if (!line.startsWith("#")) continue;
            var m = REPORTED.matcher(line);
            while (m.find()) {
                try {
                    best = Math.max(best, Integer.parseInt(m.group(1)));
                } catch (NumberFormatException ignored) {
                    // A number too large to be a count is not one.
                }
            }
        }
        return best;
    }

    /** First non-empty comment line, which is where these tools put their totals. */
    private static String headline(String report) {
        if (report == null) return "";
        for (var line : report.split("\n")) {
            var t = line.trim();
            if (t.startsWith("#") && t.length() > 2 && !t.startsWith("# format=")) {
                return t.substring(1).trim();
            }
        }
        return "";
    }

    /**
     * Total and named function counts.
     *
     * <p>Deliberately not {@link NebulaAssertNamer#survey}: that also walks every
     * defined string and every assert-helper xref to build its readiness figures,
     * which costs minutes on a 76k-function client. This runs twice per job and
     * needs only the two counters, so it walks the function manager and nothing
     * else.
     */
    private static Map<String, Long> surveyCounts(PluginContext ctx, Map<String, String> q) {
        var out = new HashMap<String, Long>();
        try {
            ctx.withProgram(program -> {
                long total = 0;
                long named = 0;
                for (var f : program.getFunctionManager().getFunctions(true)) {
                    if (f.isExternal() || f.isThunk()) continue;
                    total++;
                    if (!Responses.isAutoName(f.getName())) named++;
                }
                out.put("functions", total);
                out.put("named_functions", named);
                out.put("auto_named", total - named);
                return "";
            });
        } catch (Exception | LinkageError ignored) {
            // A counting failure should not abort the run; the report degrades.
        }
        return out;
    }

    private static String report(Job job, Map<String, Long> before, Map<String, Long> after) {
        var sb = new StringBuilder(4096);
        sb.append("# nebula_bootstrap job=").append(job.id)
          .append(" apply=").append(job.apply)
          .append(" decompile=").append(job.decompile).append('\n');
        if (!job.apply) {
            sb.append("# DRY RUN — nothing was written. Re-run with apply=true to commit.\n");
        }

        long namedBefore = before.getOrDefault("named_functions", -1L);
        long namedAfter = after.getOrDefault("named_functions", -1L);
        long total = after.getOrDefault("functions", before.getOrDefault("functions", 0L));

        appendProgress(sb, job);
        sb.append("# rows marked ok were committed; preview rows are dry-run proposals\n");

        sb.append('\n').append("## totals\n");
        appendKv(sb, "functions", total);
        if (namedBefore >= 0) appendKv(sb, "named_before", namedBefore);
        if (namedAfter >= 0) {
            appendKv(sb, "named_after", namedAfter);
            if (namedBefore >= 0) appendKv(sb, "named_delta", namedAfter - namedBefore);
            if (total > 0) {
                sb.append("named_pct\t")
                  .append(String.format(Locale.ROOT, "%.1f%%", (namedAfter * 100.0) / total))
                  .append('\n');
            }
        }
        int rows = 0;
        int failed = 0;
        synchronized (job.steps) {
            for (var s : job.steps) {
                rows += s.named();
                if ("failed".equals(s.status())) failed++;
            }
        }
        appendKv(sb, "rows_reported", rows);
        appendKv(sb, "elapsed_ms", job.elapsedMs());
        if (failed > 0) {
            sb.append("# ").append(failed)
              .append(" step(s) failed — see the detail column; the rest still ran\n");
        }

        if (job.verbose) {
            synchronized (job.outputs) {
                for (var e : job.outputs.entrySet()) {
                    sb.append('\n').append("## ").append(e.getKey()).append('\n')
                      .append(e.getValue());
                    if (!e.getValue().endsWith("\n")) sb.append('\n');
                }
            }
        } else if (!job.outputs.isEmpty()) {
            sb.append("# pass verbose=true for each step's full row-by-row output\n");
        }

        sb.append('\n').append("# next: ");
        if (!job.apply) sb.append("re-run with apply=true, then ");
        if (!job.decompile) {
            sb.append("nebula_bootstrap decompile=true (assert callers the string path missed), then ");
        }
        sb.append("factory_catalog / assert_catalog / messaging_catalog / attr_catalog "
                + "for the class, field and message indexes, then source_tree to pick a subsystem\n");
        return sb.toString();
    }

    private static void appendKv(StringBuilder sb, String key, long value) {
        sb.append(key).append('\t').append(value).append('\n');
    }

    private static boolean parseBool(String v) {
        if (v == null) return false;
        var s = v.trim().toLowerCase(Locale.ROOT);
        return s.equals("1") || s.equals("true") || s.equals("yes") || s.equals("on");
    }

    private static int parseInt(String v, int fallback) {
        if (v == null || v.isBlank()) return fallback;
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
