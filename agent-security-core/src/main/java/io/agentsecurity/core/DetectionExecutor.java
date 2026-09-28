package io.agentsecurity.core;

import java.util.concurrent.*;

/** 用固定线程和有界队列执行扩展检测，统一执行截止时间；超时后拒绝调用而非无限增加线程。 */
final class DetectionExecutor implements AutoCloseable {

    private final ThreadPoolExecutor executor;
    private final java.util.concurrent.atomic.LongAdder timeouts =
            new java.util.concurrent.atomic.LongAdder();
    private final java.util.concurrent.atomic.LongAdder errors =
            new java.util.concurrent.atomic.LongAdder();
    private final java.util.concurrent.atomic.LongAdder rejected =
            new java.util.concurrent.atomic.LongAdder();
    private final java.util.concurrent.atomic.LongAdder interrupted =
            new java.util.concurrent.atomic.LongAdder();
    private final int capacity;

    DetectionExecutor(DetectionLimits limits) {
        capacity = limits.maxConcurrency();
        executor =
                new ThreadPoolExecutor(
                        limits.maxConcurrency(),
                        limits.maxConcurrency(),
                        30,
                        TimeUnit.SECONDS,
                        new ArrayBlockingQueue<>(limits.maxConcurrency()),
                        runnable -> {
                            Thread thread = new Thread(runnable, "agent-security-detector");
                            thread.setDaemon(true);
                            thread.setContextClassLoader(ClassLoader.getSystemClassLoader());
                            return thread;
                        },
                        new ThreadPoolExecutor.AbortPolicy());
        executor.allowCoreThreadTimeOut(true);
    }

    /** 截止时间包含排队耗时；取消仅发出中断请求，线程上限负责约束不响应中断的检测器。 */
    <T> T run(Callable<T> task, long deadline) {
        if (Thread.currentThread().isInterrupted()) {
            throw blocked("detector-interrupted");
        }
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) {
            throw blocked("detector-timeout");
        }
        Future<T> future;
        try {
            future = executor.submit(task);
        } catch (RejectedExecutionException e) {
            throw blocked(executor.isShutdown() ? "detector-closed" : "detector-capacity");
        }
        try {
            remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                throw new TimeoutException();
            }
            return future.get(remaining, TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            executor.remove((Runnable) future);
            throw blocked("detector-timeout");
        } catch (InterruptedException e) {
            future.cancel(true);
            executor.remove((Runnable) future);
            Thread.currentThread().interrupt();
            throw blocked("detector-interrupted");
        } catch (ExecutionException e) {
            // 检测器异常可能携带请求内容或凭证，仅向调用方暴露稳定的错误标识。
            throw blocked("detector-error");
        } catch (CancellationException e) {
            throw blocked("detector-closed");
        }
    }

    private SecurityBlockedException blocked(String reason) {
        switch (reason) {
            case "detector-timeout" -> timeouts.increment();
            case "detector-error" -> errors.increment();
            case "detector-interrupted" -> interrupted.increment();
            case "detector-capacity", "detector-closed" -> rejected.increment();
            default -> throw new IllegalArgumentException("Unknown detector failure");
        }
        return new SecurityBlockedException(reason);
    }

    io.agentsecurity.core.health.WorkerHealth health() {
        return new io.agentsecurity.core.health.WorkerHealth(
                executor.getActiveCount(),
                executor.getQueue().size(),
                executor.getMaximumPoolSize(),
                capacity,
                executor.isShutdown(),
                false,
                timeouts.sum(),
                errors.sum(),
                rejected.sum(),
                interrupted.sum());
    }

    boolean isClosed() {
        return executor.isShutdown();
    }

    @Override
    public void close() {
        for (Runnable pending : executor.shutdownNow()) {
            if (pending instanceof Future<?> future) {
                future.cancel(false);
            }
        }
    }
}
