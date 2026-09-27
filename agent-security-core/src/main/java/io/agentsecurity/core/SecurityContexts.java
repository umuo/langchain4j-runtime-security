package io.agentsecurity.core;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.*;

/** Explicit scopes and submission-time capture; no inheritable thread-local or model-derived identity. */
public final class SecurityContexts {
    private static final ThreadLocal<Scope> CURRENT = new ThreadLocal<>();
    private SecurityContexts() { }
    public static SecurityContext current() { Scope scope = CURRENT.get(); return scope == null ? null : scope.context; }
    public static Scope open(SecurityContext context) { return restore(Objects.requireNonNull(context)); }

    /** Installs a captured snapshot; null deliberately clears ambient worker identity until close(). */
    public static Scope restore(SecurityContext context) {
        Scope scope = new Scope(context, CURRENT.get()); CURRENT.set(scope); return scope;
    }

    public static Runnable wrap(Runnable task) {
        Objects.requireNonNull(task); SecurityContext context = current();
        return () -> { try (Scope ignored = restore(context)) { task.run(); } };
    }
    public static <T> Callable<T> wrap(Callable<T> task) {
        Objects.requireNonNull(task); SecurityContext context = current();
        return () -> { try (Scope ignored = restore(context)) { return task.call(); } };
    }
    public static Executor executor(Executor delegate) {
        Objects.requireNonNull(delegate);
        if (delegate instanceof ContextExecutor || delegate instanceof ContextExecutorService) return delegate;
        if (delegate instanceof ExecutorService service) return executorService(service);
        return new ContextExecutor(delegate);
    }
    public static ExecutorService executorService(ExecutorService delegate) {
        Objects.requireNonNull(delegate);
        return delegate instanceof ContextExecutorService ? delegate : new ContextExecutorService(delegate);
    }

    public static final class Scope implements AutoCloseable {
        private final SecurityContext context;
        private final Scope previous;
        private final Thread owner = Thread.currentThread();
        private boolean closed;
        private Scope(SecurityContext context, Scope previous) { this.context = context; this.previous = previous; }
        @Override public void close() {
            if (owner != Thread.currentThread()) throw new IllegalStateException("Security scope must close on its owning thread");
            if (closed) return;
            if (CURRENT.get() != this) throw new IllegalStateException("Security scopes must close in reverse order");
            if (previous == null) CURRENT.remove(); else CURRENT.set(previous);
            closed = true;
        }
    }

    private record ContextExecutor(Executor delegate) implements Executor {
        @Override public void execute(Runnable task) { delegate.execute(wrap(task)); }
    }
    private static final class ContextExecutorService extends AbstractExecutorService {
        private final ExecutorService delegate;
        private ContextExecutorService(ExecutorService delegate) { this.delegate = delegate; }
        @Override public void execute(Runnable task) { delegate.execute(wrap(task)); }
        @Override public void shutdown() { delegate.shutdown(); }
        @Override public List<Runnable> shutdownNow() { return delegate.shutdownNow(); }
        @Override public boolean isShutdown() { return delegate.isShutdown(); }
        @Override public boolean isTerminated() { return delegate.isTerminated(); }
        @Override public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException { return delegate.awaitTermination(timeout, unit); }
    }
}
