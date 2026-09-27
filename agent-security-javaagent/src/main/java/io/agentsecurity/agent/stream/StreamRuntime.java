package io.agentsecurity.agent.stream;

import java.util.concurrent.*;

/** 管理流保护器共享容量、超时调度与通知线程，避免慢业务回调阻塞唯一计时线程。 */
final class StreamRuntime {

    static StreamLimits limits;

    private static Semaphore permits;

    private static ScheduledThreadPoolExecutor timers;

    private static ThreadPoolExecutor notifications;

    public static void initialize(StreamLimits config) {
        if (timers != null) {
            timers.shutdownNow();
        }
        if (notifications != null) {
            notifications.shutdownNow();
        }
        limits = config;
        permits = new Semaphore(config.maxActive());
        timers =
                new ScheduledThreadPoolExecutor(
                        1, task -> daemon(task, "agent-security-stream-timer"));
        timers.setRemoveOnCancelPolicy(true);
        notifications =
                new ThreadPoolExecutor(
                        2,
                        2,
                        0,
                        TimeUnit.MILLISECONDS,
                        new ArrayBlockingQueue<>(config.maxActive()),
                        task -> daemon(task, "agent-security-stream-notification"));
    }

    private static Thread daemon(Runnable runnable, String name) {
        Thread thread = new Thread(runnable, name);
        thread.setDaemon(true);
        thread.setContextClassLoader(ClassLoader.getSystemClassLoader());
        return thread;
    }

    public static boolean acquire() {
        return permits.tryAcquire();
    }

    public static void release() {
        permits.release();
    }

    public static ScheduledFuture<?> schedule(Runnable action) {
        return timers.schedule(action, limits.timeoutMillis(), TimeUnit.MILLISECONDS);
    }

    public static void notifyLater(Runnable action) {
        notifications.execute(action);
    }
}
