package io.agentsecurity.core;

import java.util.concurrent.*;

/** 用固定线程和有界队列执行扩展检测，统一执行截止时间；超时后拒绝调用而非无限增加线程。 */
final class DetectionExecutor implements AutoCloseable {

    private final ThreadPoolExecutor executor;

    DetectionExecutor(DetectionLimits limits) {
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
            throw new SecurityBlockedException("detector-interrupted");
        }
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) {
            throw new SecurityBlockedException("detector-timeout");
        }
        Future<T> future;
        try {
            future = executor.submit(task);
        } catch (RejectedExecutionException e) {
            throw new SecurityBlockedException(
                    executor.isShutdown() ? "detector-closed" : "detector-capacity");
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
            throw new SecurityBlockedException("detector-timeout");
        } catch (InterruptedException e) {
            future.cancel(true);
            executor.remove((Runnable) future);
            Thread.currentThread().interrupt();
            throw new SecurityBlockedException("detector-interrupted");
        } catch (ExecutionException e) {
            // 检测器异常可能携带请求内容或凭证，仅向调用方暴露稳定的错误标识。
            throw new SecurityBlockedException("detector-error");
        } catch (CancellationException e) {
            throw new SecurityBlockedException("detector-closed");
        }
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
