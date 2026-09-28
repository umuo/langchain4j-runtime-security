package io.agentsecurity.core;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.health.AgentCoverage;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/** 检查诊断不会改变拒绝行为，且停滞的执行仍可在快照中观察。 */
class HealthTest {
    private final SecurityEvent event =
            new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "test", "secret");

    @Test
    void timedOutUninterruptibleWorkerRemainsVisibleAndDerivedEngineSharesCounters()
            throws Exception {
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        try (var engine =
                new PolicyEngine(
                        List.of(
                                e -> {
                                    entered.countDown();
                                    while (release.getCount() != 0) {
                                        try {
                                            release.await();
                                        } catch (InterruptedException ignored) {
                                            // 模拟忽略中断的第三方检测器，finally 中必须释放。
                                        }
                                    }
                                    return Decision.allow();
                                }),
                        (e, d) -> {},
                        new DetectionLimits(Duration.ofMillis(200), 1))) {
            var derived = engine.withAdditionalDetectors(List.of());
            assertEquals(
                    "detector-timeout",
                    assertThrows(SecurityBlockedException.class, () -> derived.check(event))
                            .ruleId());
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            var state = engine.detectorHealth();
            assertEquals(1, state.timeouts());
            assertEquals(1, state.active());
            assertEquals(0, state.queued());
            assertEquals(1, state.capacity());
            assertEquals(state, derived.detectorHealth());
        } finally {
            release.countDown();
        }
    }

    @Test
    void auditFailureIsStickyAndLaterCallsCountAsRejected() {
        var audit =
                new BoundedAuditSink(
                        (e, d) -> {
                            throw new IllegalStateException("secret");
                        },
                        Duration.ofSeconds(1),
                        2);
        try (audit) {
            assertThrows(IllegalStateException.class, () -> audit.accept(event, Decision.allow()));
            assertThrows(IllegalStateException.class, () -> audit.accept(event, Decision.allow()));
            assertTrue(audit.health().failed());
            assertFalse(audit.health().closed());
            assertEquals(1, audit.health().errors());
            assertEquals(1, audit.health().rejected());
            assertEquals(2, audit.health().capacity());
        }
        assertTrue(audit.health().closed());
    }

    @Test
    void auditQueueAndActiveWriterAreVisibleWithoutWaitingForDelegate() throws Exception {
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var callers = Executors.newSingleThreadExecutor();
        try (var audit =
                new BoundedAuditSink(
                        (e, d) -> {
                            entered.countDown();
                            try {
                                release.await();
                            } catch (InterruptedException interrupted) {
                                Thread.currentThread().interrupt();
                            }
                        },
                        Duration.ofSeconds(5),
                        3)) {
            var pending = callers.submit(() -> audit.accept(event, Decision.allow()));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            assertEquals(1, audit.health().active());
            assertEquals(0, audit.health().queued());
            release.countDown();
            pending.get(2, TimeUnit.SECONDS);
            assertFalse(audit.health().failed());
        } finally {
            release.countDown();
            callers.shutdownNow();
        }
    }

    @Test
    void coverageIsBoundedImmutableAndDoesNotClaimProtectionBeforeInstall() {
        var coverage = new AgentCoverage();
        assertFalse(coverage.snapshot().installed());
        assertNull(coverage.snapshot().detector());
        for (int i = 0; i < 140; i++) {
            coverage.transformed("example.Model" + i);
        }
        coverage.transformed("secret\ninvalid");
        coverage.installed();
        coverage.transformationFailed();
        var snapshot = coverage.snapshot();
        assertTrue(snapshot.installed());
        assertTrue(snapshot.failed());
        assertEquals(141, snapshot.transformations());
        assertEquals(128, snapshot.transformedTypes().size());
        assertEquals(13, snapshot.omittedNames());
        assertThrows(
                UnsupportedOperationException.class, () -> snapshot.transformedTypes().clear());
    }
}
