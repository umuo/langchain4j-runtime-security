package io.agentsecurity.core.telemetry;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.*;
import io.agentsecurity.core.delegation.*;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/** 验证故障隔离、有限资源、脱敏数据和真实父子委托关联。 */
class SecurityTelemetryTest {
    private SecurityEvent event() {
        return new SecurityEvent(
                UUID.randomUUID(),
                SecurityEvent.Phase.TOOL_INPUT,
                "secret-operation",
                "secret-prompt",
                SecurityContext.authenticated(
                        "secret-tenant", "secret-principal", Set.of("secret-permission")));
    }

    private long count(SecurityTelemetry telemetry, SecurityTelemetry.Outcome outcome) {
        return telemetry.snapshot().metrics().stream()
                .filter(m -> m.outcome() == outcome)
                .mapToLong(SecurityTelemetry.Metric::count)
                .sum();
    }

    @Test
    void boundedQueueDoesNotLoseMetricsAndDoesNotRetainSecrets() {
        var telemetry = new SecurityTelemetry(1, 1);
        var event = event();
        telemetry.record(event, SecurityTelemetry.Outcome.ALLOW, 1000000);
        telemetry.record(event, SecurityTelemetry.Outcome.ALLOW, 1000001);
        assertEquals(2, count(telemetry, SecurityTelemetry.Outcome.ALLOW));
        assertEquals(1, telemetry.snapshot().dropped());
        var records = telemetry.drain(10);
        assertEquals(1, records.size());
        assertEquals(event.id(), records.get(0).eventId());
        assertEquals(event.context().runId(), records.get(0).runId());
        assertFalse(records.toString().contains("secret"));
        var metric =
                telemetry.snapshot().metrics().stream()
                        .filter(m -> m.count() > 0)
                        .findFirst()
                        .orElseThrow();
        assertEquals(List.of(1L, 1L, 0L, 0L, 0L), metric.durationBuckets());
        assertThrows(UnsupportedOperationException.class, () -> records.clear());
    }

    @Test
    void samplingOnlyAffectsCorrelationRecords() {
        var telemetry = new SecurityTelemetry(10, 3);
        for (int i = 0; i < 10; i++) {
            telemetry.record(
                    new SecurityEvent(
                            java.util.UUID.randomUUID(),
                            SecurityEvent.Phase.TOOL_INPUT,
                            "lookup",
                            "",
                            null),
                    SecurityTelemetry.Outcome.DENY,
                    0);
        }
        assertEquals(10, count(telemetry, SecurityTelemetry.Outcome.DENY));
        assertEquals(4, telemetry.drain(10).size());
        assertEquals(0, telemetry.snapshot().dropped());
    }

    @Test
    void auditFailureOverridesAllowAndQueueSaturationCannotAllowDeniedOperation() {
        var telemetry = new SecurityTelemetry(1, 1);
        try (var engine =
                new PolicyEngine(
                        List.of(),
                        (e, d) -> {
                            throw new IllegalStateException();
                        },
                        DetectionLimits.defaults(),
                        telemetry)) {
            assertEquals(
                    "audit-error",
                    assertThrows(SecurityBlockedException.class, () -> engine.check(event()))
                            .ruleId());
        }
        try (var engine =
                new PolicyEngine(
                        List.of(e -> Decision.deny("policy-denied")),
                        (e, d) -> {},
                        DetectionLimits.defaults(),
                        telemetry)) {
            assertThrows(SecurityBlockedException.class, () -> engine.check(event()));
        }
        assertEquals(1, count(telemetry, SecurityTelemetry.Outcome.AUDIT_FAILURE));
        assertEquals(1, count(telemetry, SecurityTelemetry.Outcome.DENY));
        assertEquals(1, telemetry.snapshot().dropped());
    }

    @Test
    void derivedEngineSharesTelemetryAndDetectorErrorsAreCounted() {
        var telemetry = new SecurityTelemetry(10, 1);
        try (var engine =
                        new PolicyEngine(
                                List.of(), (e, d) -> {}, DetectionLimits.defaults(), telemetry);
                var derived =
                        engine.withAdditionalDetectors(
                                List.of(
                                        e -> {
                                            throw new IllegalStateException();
                                        }))) {
            engine.check(event());
            assertThrows(SecurityBlockedException.class, () -> derived.check(event()));
        }
        assertEquals(1, count(telemetry, SecurityTelemetry.Outcome.ALLOW));
        assertEquals(1, count(telemetry, SecurityTelemetry.Outcome.DETECTOR_FAILURE));
    }

    @Test
    void concurrentWritersHaveExactCountsAndBoundedStorage() throws Exception {
        var telemetry = new SecurityTelemetry(4, 1);
        var pool = Executors.newFixedThreadPool(4);
        try {
            var event = event();
            for (int i = 0; i < 4; i++) {
                pool.submit(
                        () -> {
                            for (int j = 0; j < 1000; j++) {
                                telemetry.record(event, SecurityTelemetry.Outcome.ALLOW, 0);
                            }
                        });
            }
        } finally {
            pool.shutdown();
        }
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        assertEquals(4000, count(telemetry, SecurityTelemetry.Outcome.ALLOW));
        assertEquals(3996, telemetry.snapshot().dropped());
        assertEquals(4, telemetry.drain(10).size());
    }

    @Test
    void parentChildLifecycleAndDecisionsShareIdentifiers() throws Exception {
        var telemetry = new SecurityTelemetry(20, 1);
        var grant = AgentGrant.tools(Set.of("read"), Set.of("lookup"));
        var definitions =
                List.of(
                        new AgentDefinition("parent", grant, Set.of("child")),
                        new AgentDefinition("child", grant, Set.of()));
        try (var runtime =
                        new AgentRuntime(
                                definitions,
                                AgentRuntimeLimits.defaults(),
                                (e, d) -> {},
                                telemetry);
                var engine =
                        new PolicyEngine(
                                List.of(), (e, d) -> {}, DetectionLimits.defaults(), telemetry)) {
            var root =
                    runtime.startRoot(
                            "parent",
                            SecurityContext.authenticated("tenant", "user", Set.of("read")),
                            grant,
                            Duration.ofSeconds(5));
            root.call(
                    () -> {
                        var child = runtime.delegate("child", grant, Duration.ofSeconds(2));
                        return child.call(
                                () -> {
                                    engine.check(
                                            new SecurityEvent(
                                                    SecurityEvent.Phase.TOOL_INPUT,
                                                    "lookup",
                                                    "secret"));
                                    return null;
                                });
                    });
            var records = telemetry.drain(20);
            assertEquals(5, records.size());
            var child =
                    records.stream()
                            .filter(r -> r.phase() == SecurityEvent.Phase.AGENT_DELEGATE)
                            .findFirst()
                            .orElseThrow();
            var decision =
                    records.stream()
                            .filter(r -> r.phase() == SecurityEvent.Phase.TOOL_INPUT)
                            .findFirst()
                            .orElseThrow();
            assertEquals(root.invocationId(), child.parentInvocationId());
            assertEquals(child.invocationId(), decision.invocationId());
            assertTrue(records.stream().allMatch(r -> r.runId().equals(root.rootRunId())));
        }
    }

    @Test
    void lifecycleAuditFailureIsStillBlocking() {
        var telemetry = new SecurityTelemetry(10, 1);
        var grant = AgentGrant.tools(Set.of(), Set.of());
        try (var runtime =
                new AgentRuntime(
                        List.of(new AgentDefinition("parent", grant, Set.of())),
                        AgentRuntimeLimits.defaults(),
                        (e, d) -> {
                            throw new IllegalStateException();
                        },
                        telemetry)) {
            assertThrows(
                    SecurityBlockedException.class,
                    () ->
                            runtime.startRoot(
                                    "parent",
                                    SecurityContext.authenticated("tenant", "user", Set.of()),
                                    grant,
                                    Duration.ofSeconds(1)));
            // 创建审计失败和随后终止登记各有一条失败遥测。
            assertEquals(2, count(telemetry, SecurityTelemetry.Outcome.AUDIT_FAILURE));
            var records = telemetry.drain(10);
            assertEquals(SecurityEvent.Phase.AGENT_START, records.get(0).phase());
            assertEquals(AgentEndReason.AUDIT_FAILED, records.get(1).endReason());
        }
    }

    @Test
    void disabledAndConfigurationBounds() {
        var telemetry = SecurityTelemetry.disabled();
        telemetry.record(event(), SecurityTelemetry.Outcome.ALLOW, 1);
        assertTrue(telemetry.snapshot().metrics().isEmpty());
        assertTrue(telemetry.drain(1).isEmpty());
        assertThrows(IllegalArgumentException.class, () -> new SecurityTelemetry(0, 1));
        assertThrows(IllegalArgumentException.class, () -> new SecurityTelemetry(1, 0));
        assertThrows(IllegalArgumentException.class, () -> new SecurityTelemetry(65537, 1));
        assertThrows(IllegalArgumentException.class, () -> telemetry.drain(0));
    }
}
