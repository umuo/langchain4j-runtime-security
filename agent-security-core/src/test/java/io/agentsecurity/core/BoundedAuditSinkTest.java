package io.agentsecurity.core;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class BoundedAuditSinkTest {
    private final SecurityEvent event = new SecurityEvent(SecurityEvent.Phase.MODEL_INPUT, "chat", "private");

    @Test void waitForAcknowledgementBeforeReleasingProtectedOperation() throws Exception {
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        var caller = Executors.newSingleThreadExecutor();
        try (var sink = new BoundedAuditSink((e,d) -> {
            entered.countDown();
            try { release.await(); } catch (InterruptedException ex) { throw new IllegalStateException(); }
        }, Duration.ofSeconds(2), 2); var engine = new PolicyEngine(List.of(), sink)) {
            Future<?> result = caller.submit(() -> engine.check(event));
            assertTrue(entered.await(1, TimeUnit.SECONDS)); assertFalse(result.isDone());
            release.countDown(); result.get(2, TimeUnit.SECONDS);
        } finally { release.countDown(); caller.shutdownNow(); }
    }

    @Test void slowUninterruptibleSinkTimesOutAndFurtherCallsFailClosed() {
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger writes = new AtomicInteger();
        try (var sink = new BoundedAuditSink((e,d) -> {
            writes.incrementAndGet();
            while (release.getCount() > 0) {
                try { release.await(); } catch (InterruptedException ignored) { }
            }
        }, Duration.ofMillis(100), 1); var engine = new PolicyEngine(List.of(), sink)) {
            assertTimeoutPreemptively(Duration.ofSeconds(2), () ->
                    assertEquals("audit-error", assertThrows(SecurityBlockedException.class, () -> engine.check(event)).ruleId()));
            for (int i = 0; i < 20; i++) assertThrows(SecurityBlockedException.class, () -> engine.check(event));
            assertEquals(1, writes.get());
        } finally { release.countDown(); }
    }

    @Test void writeFailureIsLatchedAndPrivateErrorIsNotPropagated() {
        AtomicInteger writes = new AtomicInteger();
        try (var sink = new BoundedAuditSink((e,d) -> {
            writes.incrementAndGet(); throw new IllegalStateException("confidential disk detail");
        }, Duration.ofSeconds(1), 2); var engine = new PolicyEngine(List.of(), sink)) {
            for (int i = 0; i < 3; i++) {
                var error = assertThrows(SecurityBlockedException.class, () -> engine.check(event));
                assertEquals("audit-error", error.ruleId()); assertNull(error.getCause());
            }
            assertEquals(1, writes.get());
        }
    }

    @Test void saturatedQueueRejectsCallersWithOnlyOneWriter() throws Exception {
        CountDownLatch started = new CountDownLatch(1), release = new CountDownLatch(1);
        AtomicInteger writes = new AtomicInteger();
        ExecutorService callers = Executors.newFixedThreadPool(8);
        try (var sink = new BoundedAuditSink((e,d) -> {
            writes.incrementAndGet(); started.countDown();
            while (release.getCount() > 0) {
                try { release.await(); } catch (InterruptedException ignored) { }
            }
        }, Duration.ofMillis(500), 1); var engine = new PolicyEngine(List.of(), sink)) {
            Callable<String> check = () -> {
                try { engine.check(event); return "allowed"; }
                catch (SecurityBlockedException denied) { return denied.ruleId(); }
            };
            var tasks = new java.util.ArrayList<Future<String>>();
            tasks.add(callers.submit(check));
            assertTrue(started.await(1, TimeUnit.SECONDS));
            for (int i = 0; i < 7; i++) tasks.add(callers.submit(check));
            for (var task : tasks) assertEquals("audit-error", task.get(2, TimeUnit.SECONDS));
            assertEquals(1, writes.get());
        } finally { release.countDown(); callers.shutdownNow(); }
    }
}
