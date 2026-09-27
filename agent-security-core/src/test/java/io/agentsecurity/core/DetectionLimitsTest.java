package io.agentsecurity.core;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class DetectionLimitsTest {
    private final SecurityEvent event = new SecurityEvent(SecurityEvent.Phase.MODEL_INPUT, "chat", "confidential payload");

    @Test void slowDetectorTimesOutWithoutAllowingOperation() {
        var audited = new java.util.concurrent.atomic.AtomicReference<Decision>();
        try (var engine = new PolicyEngine(List.of(e -> {
            try { Thread.sleep(10_000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            return Decision.allow();
        }), (e, d) -> audited.set(d), new DetectionLimits(Duration.ofMillis(80), 1))) {
            assertTimeoutPreemptively(Duration.ofSeconds(2), () ->
                    assertEquals("detector-timeout", assertThrows(SecurityBlockedException.class, () -> engine.check(event)).ruleId()));
            assertFalse(audited.get().allowed());
        }
    }

    @Test void chainUsesOneBudgetRatherThanOneTimeoutPerDetector() {
        Detector slow = e -> {
            try { Thread.sleep(100); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            return Decision.allow();
        };
        try (var engine = new PolicyEngine(List.of(slow, slow, slow), (e,d) -> {}, new DetectionLimits(Duration.ofMillis(150), 1))) {
            assertEquals("detector-timeout", assertThrows(SecurityBlockedException.class, () -> engine.check(event)).ruleId());
        }
    }

    @Test void uninterruptibleDetectorCannotCreateUnboundedWorkersOrQueuedRequests() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger active = new AtomicInteger();
        AtomicInteger max = new AtomicInteger();
        Detector stuck = e -> {
            int current = active.incrementAndGet(); max.accumulateAndGet(current, Math::max);
            try {
                while (release.getCount() != 0) {
                    try { release.await(); } catch (InterruptedException ignored) { }
                }
                return Decision.allow();
            } finally { active.decrementAndGet(); }
        };
        ExecutorService callers = Executors.newFixedThreadPool(8);
        try (var engine = new PolicyEngine(List.of(stuck), (e,d) -> {}, new DetectionLimits(Duration.ofMillis(150), 2))) {
            var tasks = new java.util.ArrayList<Future<String>>();
            for (int i = 0; i < 8; i++) tasks.add(callers.submit(() -> {
                try { engine.check(event); return "allowed"; }
                catch (SecurityBlockedException denied) { return denied.ruleId(); }
            }));
            var reasons = new java.util.ArrayList<String>();
            for (Future<String> task : tasks) reasons.add(task.get(3, TimeUnit.SECONDS));
            assertFalse(reasons.contains("allowed")); assertTrue(reasons.contains("detector-capacity"));
            assertTrue(max.get() <= 2); assertTrue(max.get() > 0);
        } finally { release.countDown(); callers.shutdownNow(); }
    }

    @Test void shutdownAndInterruptionAreExplicitDenials() {
        var engine = new PolicyEngine(List.of(e -> Decision.allow()), (e,d) -> {});
        engine.close();
        assertEquals("detector-closed", assertThrows(SecurityBlockedException.class, () -> engine.check(event)).ruleId());
        try (var interrupted = new PolicyEngine(List.of(e -> Decision.allow()), (e,d) -> {})) {
            Thread.currentThread().interrupt();
            try {
                assertEquals("detector-interrupted", assertThrows(SecurityBlockedException.class, () -> interrupted.check(event)).ruleId());
                assertTrue(Thread.currentThread().isInterrupted());
            } finally { Thread.interrupted(); }
        }
    }

    @Test void derivedEngineSharesTheSameResourceLimits() {
        try (var engine = new PolicyEngine(List.of(), (e,d) -> {}, new DetectionLimits(Duration.ofMillis(50), 1))) {
            var derived = engine.withAdditionalDetectors(List.of(e -> {
                try { Thread.sleep(5000); } catch (InterruptedException ignored) { }
                return Decision.allow();
            }));
            assertEquals("detector-timeout", assertThrows(SecurityBlockedException.class, () -> derived.check(event)).ruleId());
            engine.close();
            assertEquals("detector-closed", assertThrows(SecurityBlockedException.class, () -> derived.check(event)).ruleId());
        }
    }

    @Test void pluginConstructionIsAlsoTimeBounded() {
        try (var engine = new PolicyEngine(List.of(), (e,d) -> {}, new DetectionLimits(Duration.ofMillis(50), 1))) {
            assertEquals("detector-timeout", assertThrows(SecurityBlockedException.class, () -> engine.loadDetectors(() -> {
                Thread.sleep(5000); return List.of();
            })).ruleId());
        }
    }
}
