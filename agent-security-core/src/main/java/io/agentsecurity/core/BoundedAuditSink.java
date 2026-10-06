package io.agentsecurity.core;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

/** 单写线程与有界队列审计。写入失败、超时或队列饱和后持续拒绝，直至实例重建。 */
public final class BoundedAuditSink implements BiConsumer<SecurityEvent, Decision>, AutoCloseable {

    private final BiConsumer<SecurityEvent, Decision> delegate;

    private final ThreadPoolExecutor writer;

    private final long timeoutNanos;

    private final AtomicBoolean failed = new AtomicBoolean();
    private final java.util.concurrent.atomic.LongAdder timeouts =
            new java.util.concurrent.atomic.LongAdder();
    private final java.util.concurrent.atomic.LongAdder errors =
            new java.util.concurrent.atomic.LongAdder();
    private final java.util.concurrent.atomic.LongAdder rejected =
            new java.util.concurrent.atomic.LongAdder();
    private final java.util.concurrent.atomic.LongAdder interrupted =
            new java.util.concurrent.atomic.LongAdder();
    private final int capacity;

    public BoundedAuditSink(
            BiConsumer<SecurityEvent, Decision> delegate, Duration timeout, int capacity) {
        this.delegate = Objects.requireNonNull(delegate);
        validateSettings(timeout, capacity);
        this.capacity = capacity;
        timeoutNanos = timeout.toNanos();
        writer =
                new ThreadPoolExecutor(
                        1,
                        1,
                        0,
                        TimeUnit.SECONDS,
                        new ArrayBlockingQueue<>(capacity),
                        task -> {
                            Thread thread = new Thread(task, "agent-security-audit");
                            thread.setDaemon(true);
                            thread.setContextClassLoader(ClassLoader.getSystemClassLoader());
                            return thread;
                        },
                        new ThreadPoolExecutor.AbortPolicy()) {

                    @Override
                    protected void terminated() {
                        if (delegate instanceof AutoCloseable closeable) {
                            try {
                                closeable.close();
                            } catch (Exception ignored) {
                                errors.increment();
                                failed.set(true);
                            }
                        }
                    }
                };
    }

    /** 只校验审计等待与队列参数，不创建工作线程，供部署预检查复用。 */
    public static void validateSettings(Duration timeout, int capacity) {
        Objects.requireNonNull(timeout);
        if (timeout.isNegative()
                || timeout.isZero()
                || timeout.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalArgumentException("Invalid audit timeout");
        }
        if (capacity < 1 || capacity > 4096) {
            throw new IllegalArgumentException("Invalid audit capacity");
        }
    }

    @Override
    public void accept(SecurityEvent event, Decision decision) {
        if (failed.get() || writer.isShutdown()) {
            rejected.increment();
            throw new IllegalStateException("Audit unavailable");
        }
        Future<?> pending = null;
        long deadline = System.nanoTime() + timeoutNanos;
        try {
            pending =
                    writer.submit(
                            () -> {
                                if (failed.get()) {
                                    throw new IllegalStateException("Audit unavailable");
                                }
                                try {
                                    delegate.accept(event, decision);
                                } catch (RuntimeException | Error error) {
                                    failed.set(true);
                                    throw error;
                                }
                            });
            pending.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            if (failed.get()) {
                throw new IllegalStateException("Audit unavailable");
            }
        } catch (InterruptedException error) {
            interrupted.increment();
            failed.set(true);
            cancel(pending);
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Audit interrupted");
        } catch (ExecutionException
                | TimeoutException
                | CancellationException
                | RejectedExecutionException error) {
            if (error instanceof TimeoutException) {
                timeouts.increment();
            } else if (error instanceof RejectedExecutionException
                    || error instanceof CancellationException) {
                rejected.increment();
            } else {
                errors.increment();
            }
            failed.set(true);
            cancel(pending);
            throw new IllegalStateException("Audit unavailable");
        }
    }

    /** 失败状态包含正常关闭后的不可用状态；closed 用于区分关闭与故障。 */
    public io.agentsecurity.core.health.WorkerHealth health() {
        return new io.agentsecurity.core.health.WorkerHealth(
                writer.getActiveCount(),
                writer.getQueue().size(),
                1,
                capacity,
                writer.isShutdown(),
                failed.get(),
                timeouts.sum(),
                errors.sum(),
                rejected.sum(),
                interrupted.sum());
    }

    private void cancel(Future<?> pending) {
        if (pending != null) {
            pending.cancel(true);
            writer.remove((Runnable) pending);
        }
    }

    @Override
    public void close() {
        failed.set(true);
        for (Runnable queued : writer.shutdownNow()) {
            if (queued instanceof Future<?> future) {
                future.cancel(false);
            }
        }
        // Delegate closes on the writer after in-flight work exits; no unbounded shutdown wait.
    }
}
