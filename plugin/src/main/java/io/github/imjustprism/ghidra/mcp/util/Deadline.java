package io.github.imjustprism.ghidra.mcp.util;

import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Bounds work that can block indefinitely.
 *
 * <p>A few paths call into the OS through JNA — process enumeration, module
 * lists, live attach. If that initialisation blocks (a security product
 * inspecting the native image, a protected process, a loader lock), the HTTP
 * handler never returns and the caller sits there until <em>its</em> timeout
 * fires, having learned nothing. For an agent that is the worst outcome: the
 * whole request budget is gone and there is no error to act on.
 *
 * <p>This runs the work on a daemon thread and gives up after a deadline. The
 * stuck thread is left alone — it cannot be safely killed — but it is a daemon,
 * so it never holds up JVM shutdown, and the caller gets a real error quickly.
 */
public final class Deadline {

    private static final AtomicInteger SEQ = new AtomicInteger();

    private static final ThreadFactory THREADS = r -> {
        var t = new Thread(r, "ghidra-mcp-deadline-" + SEQ.incrementAndGet());
        t.setDaemon(true);
        return t;
    };

    private Deadline() {}

    /**
     * Run {@code work}, failing with {@link IllegalStateException} if it has not
     * finished within {@code seconds}.
     *
     * @param what human-readable name of the operation, used in the error
     */
    public static <T> T call(String what, int seconds, Callable<T> work) {
        var executor = Executors.newSingleThreadExecutor(THREADS);
        try {
            var future = CompletableFuture.supplyAsync(() -> {
                try {
                    return work.call();
                } catch (Exception e) {
                    throw new IllegalStateException(e.getMessage(), e);
                }
            }, executor);
            return future.get(Math.max(1, seconds), TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new IllegalStateException(what + " did not respond within " + seconds
                    + "s and was abandoned. This is usually the native/JNA path blocking: "
                    + "check that Ghidra has permission to open the target process "
                    + "(run Ghidra elevated), and that no security product is holding "
                    + "the loader lock.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(what + " was interrupted");
        } catch (ExecutionException e) {
            var cause = e.getCause();
            if (cause instanceof RuntimeException re) throw re;
            throw new IllegalStateException(what + " failed: " + String.valueOf(cause), cause);
        } finally {
            // Do not await termination: the point is that the worker may be stuck.
            executor.shutdownNow();
        }
    }
}
