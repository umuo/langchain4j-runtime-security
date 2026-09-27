package io.agentsecurity.agent;

import java.util.concurrent.*;

/** One shared capacity budget for callback and Flow streams. */
final class StreamRuntime {
    static StreamLimits limits;
    private static Semaphore permits;
    private static ScheduledThreadPoolExecutor timers;
    private static ThreadPoolExecutor notifications;

    static void initialize(StreamLimits config) {
        if (timers != null) timers.shutdownNow();
        if (notifications != null) notifications.shutdownNow();
        limits = config;
        permits = new Semaphore(config.maxActive());
        timers = new ScheduledThreadPoolExecutor(1, task -> daemon(task, "agent-security-stream-timer"));
        timers.setRemoveOnCancelPolicy(true);
        notifications = new ThreadPoolExecutor(2, 2, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(config.maxActive()), task -> daemon(task, "agent-security-stream-notification"));
    }

    private static Thread daemon(Runnable runnable, String name) {
        Thread thread = new Thread(runnable, name);
        thread.setDaemon(true);
        thread.setContextClassLoader(ClassLoader.getSystemClassLoader());
        return thread;
    }

    static boolean acquire() { return permits.tryAcquire(); }
    static void release() { permits.release(); }
    static ScheduledFuture<?> schedule(Runnable action) {
        return timers.schedule(action, limits.timeoutMillis(), TimeUnit.MILLISECONDS);
    }
    static void notifyLater(Runnable action) { notifications.execute(action); }
}
