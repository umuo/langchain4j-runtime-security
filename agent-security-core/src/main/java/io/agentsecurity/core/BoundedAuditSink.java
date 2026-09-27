package io.agentsecurity.core;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

/** Acknowledged writes with a bounded queue and wait. Any write failure disables this sink until restart. */
public final class BoundedAuditSink implements BiConsumer<SecurityEvent, Decision>, AutoCloseable {
    private final BiConsumer<SecurityEvent, Decision> delegate;
    private final ThreadPoolExecutor writer;
    private final long timeoutNanos;
    private final AtomicBoolean failed = new AtomicBoolean();

    public BoundedAuditSink(BiConsumer<SecurityEvent, Decision> delegate, Duration timeout, int capacity) {
        this.delegate = Objects.requireNonNull(delegate);
        if (timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofSeconds(60)) > 0)
            throw new IllegalArgumentException("Invalid audit timeout");
        if (capacity < 1 || capacity > 4096) throw new IllegalArgumentException("Invalid audit capacity");
        timeoutNanos = timeout.toNanos();
        writer = new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(capacity), task -> {
            Thread thread = new Thread(task, "agent-security-audit");
            thread.setDaemon(true);
            thread.setContextClassLoader(ClassLoader.getSystemClassLoader());
            return thread;
        }, new ThreadPoolExecutor.AbortPolicy()) {
            @Override protected void terminated() {
                if (delegate instanceof AutoCloseable closeable) {
                    try { closeable.close(); } catch (Exception ignored) { failed.set(true); }
                }
            }
        };
    }

    @Override public void accept(SecurityEvent event, Decision decision) {
        if (failed.get() || writer.isShutdown()) throw new IllegalStateException("Audit unavailable");
        Future<?> pending = null;
        long deadline = System.nanoTime() + timeoutNanos;
        try {
            pending = writer.submit(() -> {
                if (failed.get()) throw new IllegalStateException("Audit unavailable");
                try { delegate.accept(event, decision); }
                catch (RuntimeException | Error error) { failed.set(true); throw error; }
            });
            pending.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            if (failed.get()) throw new IllegalStateException("Audit unavailable");
        } catch (InterruptedException error) {
            failed.set(true);
            cancel(pending);
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Audit interrupted");
        } catch (ExecutionException | TimeoutException | CancellationException | RejectedExecutionException error) {
            failed.set(true);
            cancel(pending);
            throw new IllegalStateException("Audit unavailable");
        }
    }

    private void cancel(Future<?> pending) {
        if (pending != null) {
            pending.cancel(true);
            writer.remove((Runnable) pending);
        }
    }

    @Override public void close() {
        failed.set(true);
        for (Runnable queued : writer.shutdownNow())
            if (queued instanceof Future<?> future) future.cancel(false);
        // Delegate closes on the writer after in-flight work exits; no unbounded shutdown wait.
    }
}
