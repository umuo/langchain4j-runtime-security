package io.agentsecurity.agent;

import io.agentsecurity.core.SecurityBlockedException;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.concurrent.Flow;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Cold, per-subscription full validation followed by demand-aware delivery of the original events. */
final class GuardedPublisher implements Flow.Publisher<Object> {
    private final Object request;
    private final Flow.Publisher<?> source;

    GuardedPublisher(Object request, Flow.Publisher<?> source) {
        this.request = request; this.source = Objects.requireNonNull(source);
    }

    @Override public void subscribe(Flow.Subscriber<? super Object> subscriber) {
        Objects.requireNonNull(subscriber);
        Session session = new Session(subscriber);
        try { subscriber.onSubscribe(session); }
        catch (Throwable consumerFailure) { session.cancel(); return; }
        session.start();
    }

    private final class Session implements Flow.Subscription, Flow.Subscriber<Object> {
        private final Flow.Subscriber<? super Object> downstream;
        private final ArrayDeque<Object> pending = new ArrayDeque<>();
        private final ReactiveContent content = new ReactiveContent(request);
        private final AtomicInteger draining = new AtomicInteger();
        private Flow.Subscription upstream;
        private ScheduledFuture<?> timer;
        private long deadline;
        private long demand;
        private Throwable failure;
        private boolean enabled, acquired, ready, sourceDone, cancelled, disposed, notificationPending;

        Session(Flow.Subscriber<? super Object> downstream) { this.downstream = downstream; }

        void start() {
            synchronized (this) { enabled = true; }
            try {
                synchronized (this) {
                    if (cancelled || failure != null) { drain(); return; }
                    if (!StreamRuntime.acquire()) throw new SecurityBlockedException("stream-capacity");
                    acquired = true;
                    deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(StreamRuntime.limits.timeoutMillis());
                    timer = StreamRuntime.schedule(this::timeout);
                }
                Bridge.before(request); // Re-check for every subscription, before starting the upstream request.
                synchronized (this) {
                    if (cancelled || disposed || failure != null) return;
                    if (System.nanoTime() >= deadline) throw new SecurityBlockedException("stream-timeout");
                }
                source.subscribe(this);
            } catch (Throwable error) { fail(error); }
            drain();
        }

        @Override public void onSubscribe(Flow.Subscription subscription) {
            Objects.requireNonNull(subscription);
            boolean reject;
            synchronized (this) {
                reject = upstream != null || cancelled || disposed || failure != null;
                if (!reject) upstream = subscription;
            }
            if (reject) { cancelUpstream(subscription); return; }
            try { subscription.request(Long.MAX_VALUE); } // Collect eagerly into bounded storage for whole-response validation.
            catch (Throwable error) { fail(error); }
        }

        @Override public void onNext(Object item) {
            Throwable error = null;
            synchronized (this) {
                if (sourceDone || cancelled || disposed || failure != null) return;
                try {
                    if (upstream == null) throw new SecurityBlockedException("stream-protocol-error");
                    if (System.nanoTime() >= deadline) throw new SecurityBlockedException("stream-timeout");
                    if (pending.size() >= StreamRuntime.limits.maxEvents()) throw new SecurityBlockedException("stream-buffer-limit");
                    content.add(item);
                    if (System.nanoTime() >= deadline) throw new SecurityBlockedException("stream-timeout");
                    pending.add(item);
                } catch (Throwable denied) { error = denied; }
            }
            if (error != null) fail(error);
        }

        @Override public void onError(Throwable error) {
            synchronized (this) { if (sourceDone) return; }
            fail(error == null ? new SecurityBlockedException("invalid-stream-error") : error);
        }

        @Override public void onComplete() {
            Throwable error = null;
            synchronized (this) {
                if (sourceDone || cancelled || disposed || failure != null) return;
                try {
                    if (upstream == null) throw new SecurityBlockedException("stream-protocol-error");
                    content.validate(deadline);
                    ready = true; sourceDone = true; content.clear();
                } catch (Throwable denied) { error = denied; }
            }
            if (error != null) fail(error);
            else drain();
        }

        @Override public void request(long count) {
            if (count <= 0) { fail(new IllegalArgumentException("Flow demand must be positive")); return; }
            synchronized (this) {
                if (cancelled || disposed) return;
                long total = demand + count;
                demand = total < 0 ? Long.MAX_VALUE : total;
            }
            drain();
        }

        @Override public void cancel() {
            Flow.Subscription subscription;
            synchronized (this) {
                if (cancelled || disposed) return;
                cancelled = true; subscription = upstream;
            }
            cancelUpstream(subscription);
            drain();
        }

        private void fail(Throwable error) {
            Flow.Subscription subscription;
            synchronized (this) {
                if (cancelled || disposed || failure != null) return;
                failure = error; sourceDone = true; pending.clear(); content.clear(); subscription = upstream;
            }
            cancelUpstream(subscription);
            drain();
        }

        private void timeout() {
            synchronized (this) {
                if (cancelled || disposed || failure != null) return;
                failure = new SecurityBlockedException("stream-timeout");
                sourceDone = true; pending.clear(); content.clear();
                notificationPending = true;
            }
            StreamRuntime.notifyLater(() -> {
                try { cancelUpstream(upstream); drain(); }
                finally {
                    synchronized (this) { notificationPending = false; if (disposed) release(); }
                }
            });
        }

        private void drain() {
            if (draining.getAndIncrement() != 0) return;
            int missed = 1;
            for (;;) {
                for (;;) {
                    Object item = null;
                    Throwable error = null;
                    boolean end = false, silent = false;
                    synchronized (this) {
                        if (!enabled || disposed) break;
                        if (cancelled || failure != null) {
                            disposed = true; end = true; silent = cancelled; error = failure;
                            pending.clear(); content.clear();
                        } else if (ready && pending.isEmpty()) { disposed = true; end = true; }
                        else if (ready && demand > 0) {
                            item = pending.remove();
                            if (demand != Long.MAX_VALUE) demand--;
                        } else break;
                    }
                    if (end) {
                        try {
                            if (!silent) {
                                if (error == null) downstream.onComplete(); else downstream.onError(error);
                            }
                        } catch (Throwable consumerFailure) { /* Subscriber violations must not produce a second terminal signal. */ }
                        finally { release(); }
                        break;
                    }
                    try { downstream.onNext(item); }
                    catch (Throwable consumerFailure) { cancel(); }
                }
                missed = draining.addAndGet(-missed);
                if (missed == 0) return;
            }
        }

        private synchronized void release() {
            if (timer != null) timer.cancel(false);
            if (notificationPending) return;
            if (acquired) { acquired = false; StreamRuntime.release(); }
        }
    }

    private static void cancelUpstream(Flow.Subscription subscription) {
        if (subscription != null) try { subscription.cancel(); } catch (Throwable ignored) { }
    }
}
