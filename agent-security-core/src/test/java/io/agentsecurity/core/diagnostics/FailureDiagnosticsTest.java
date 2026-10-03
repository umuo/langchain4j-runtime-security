package io.agentsecurity.core.diagnostics;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.*;
import io.agentsecurity.core.delegation.*;
import io.agentsecurity.core.diagnostics.FailureRecord.Category;
import io.agentsecurity.core.diagnostics.FailureRecord.Stage;
import io.agentsecurity.core.versioning.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;

class FailureDiagnosticsTest {
    @Test
    void boundedQueueDropsRecordsButKeepsCountersAndExceptionDetails() {
        var diagnostics = new FailureDiagnostics(1);
        for (int i = 0; i < 3; i++) {
            var error = new SecurityBlockedException("mcp-pagination-timeout");
            var record = diagnostics.record(error, Stage.MCP_EXECUTION, null, null, null, null);
            assertSame(record, error.diagnostic());
            assertEquals(Category.TIMEOUT, record.category());
        }
        assertEquals(1, diagnostics.snapshot().queued());
        assertEquals(2, diagnostics.snapshot().dropped());
        assertEquals(3, total(diagnostics));
        assertEquals(1, diagnostics.drain(1).size());
        assertTrue(diagnostics.drain(1).isEmpty());
    }

    @Test
    void concurrentPropagationPublishesOneSecurityFailure() throws Exception {
        var diagnostics = new FailureDiagnostics(8);
        var error = new SecurityBlockedException("custom-secret-rule");
        var executor = Executors.newFixedThreadPool(8);
        try {
            var tasks = new ArrayList<Callable<FailureRecord>>();
            for (int i = 0; i < 100; i++) {
                tasks.add(
                        () ->
                                diagnostics.record(
                                        new CompletionException(error),
                                        Stage.MCP_EXECUTION,
                                        null,
                                        null,
                                        null,
                                        null));
            }
            for (var future : executor.invokeAll(tasks)) {
                assertSame(error.diagnostic(), future.get());
            }
        } finally {
            executor.shutdownNow();
        }
        assertEquals(1, total(diagnostics));
        assertEquals(1, diagnostics.drain(8).size());
    }

    @Test
    void finalPolicyDecisionRetainsSelectedVersionAndExplicitEventContext() {
        var policy =
                new AtomicPolicy(
                        new PolicyRevision(
                                "v1", "a".repeat(64), event -> Decision.deny("sensitive-rule")),
                        4);
        var context = SecurityContext.authenticated("secret-tenant", "secret-user", Set.of());
        var event =
                new SecurityEvent(
                        UUID.randomUUID(),
                        SecurityEvent.Phase.MODEL_OUTPUT,
                        "secret-operation",
                        "secret-body",
                        context);
        try (var engine =
                new PolicyEngine(
                        List.of(policy),
                        (checked, decision) ->
                                policy.publish(
                                        1,
                                        new PolicyRevision(
                                                "v2",
                                                "b".repeat(64),
                                                ignored -> Decision.allow())))) {
            var denied = assertThrows(SecurityBlockedException.class, () -> engine.check(event));
            var record = denied.diagnostic();
            assertEquals(event.id(), record.eventId());
            assertEquals(context.runId(), record.runId());
            assertEquals(FailureDiagnostics.fingerprint("v1"), record.policyFingerprint());
            assertEquals("v2", policy.state().version());
            assertEquals(SecurityEvent.Phase.MODEL_OUTPUT, record.phase());
            assertFalse(record.toString().contains("secret"));
            assertEquals(
                    FailureDiagnostics.fingerprint("sensitive-rule"), record.ruleFingerprint());
        }
    }

    @Test
    void auditFailureIsDiagnosedWithoutAllowingOperation() {
        var event =
                new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "secret-tool", "secret-input");
        try (var engine =
                new PolicyEngine(
                        List.of(),
                        (checked, decision) -> {
                            throw new IllegalStateException("secret-credentials");
                        })) {
            var failure = assertThrows(SecurityBlockedException.class, () -> engine.check(event));
            assertEquals(Category.AUDIT_FAILURE, failure.diagnostic().category());
            assertEquals(event.id(), failure.diagnostic().eventId());
            assertFalse(failure.diagnostic().toString().contains("secret"));
        }
    }

    @Test
    void childIdentityLinksSurviveScopeExitWithoutRetainingIdentityObject() throws Exception {
        var grant = AgentGrant.tools(Set.of(), Set.of("lookup"));
        try (var runtime =
                        new AgentRuntime(
                                List.of(
                                        new AgentDefinition("planner", grant, Set.of("reader")),
                                        new AgentDefinition("reader", grant, Set.of())),
                                AgentRuntimeLimits.defaults(),
                                (e, d) -> {});
                var root =
                        runtime.startRoot(
                                "planner",
                                SecurityContext.authenticated("tenant", "user", Set.of()),
                                grant,
                                Duration.ofMinutes(1))) {
            var record =
                    root.call(
                            () -> {
                                try (var child =
                                        runtime.delegate("reader", grant, Duration.ofSeconds(30))) {
                                    return child.call(
                                            () ->
                                                    new FailureDiagnostics(1)
                                                            .record(
                                                                    new SecurityBlockedException(
                                                                            "mcp-response-limit"),
                                                                    Stage.MCP_OUTPUT,
                                                                    SecurityEvent.Phase
                                                                            .MCP_TOOL_OUTPUT,
                                                                    SecurityContexts.current(),
                                                                    null,
                                                                    null));
                                }
                            });
            assertEquals(root.invocationId(), record.parentInvocationId());
            assertEquals(root.rootRunId(), record.runId());
            assertNotEquals(root.invocationId(), record.invocationId());
            assertEquals(1, record.depth());
            assertNull(SecurityContexts.current());
        }
    }

    @Test
    void rawTransportAndCyclicFailuresHaveBoundedSafeProjection() {
        var diagnostics = new FailureDiagnostics(8);
        var transport =
                diagnostics.record(
                        new CompletionException(new java.io.IOException("secret-host")),
                        Stage.MCP_EXECUTION,
                        null,
                        null,
                        null,
                        null);
        assertEquals(Category.TRANSPORT_FAILURE, transport.category());
        assertNull(transport.ruleFingerprint());
        var left = new RuntimeException("secret-left");
        var right = new RuntimeException("secret-right");
        left.initCause(right);
        right.initCause(left);
        var cycle = diagnostics.record(left, Stage.MCP_EXECUTION, null, null, null, null);
        assertEquals(Category.EXECUTION_FAILURE, cycle.category());
        assertFalse(cycle.toString().contains("secret"));
        diagnostics.instrumentationFailure();
        assertEquals(Category.INSTRUMENTATION_FAILURE, diagnostics.drain(8).get(2).category());
    }

    @Test
    void invalidLimitsAndRecordFieldsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new FailureDiagnostics(0));
        var diagnostics = new FailureDiagnostics(1);
        assertThrows(IllegalArgumentException.class, () -> diagnostics.drain(0));
        assertNull(FailureDiagnostics.fingerprint("x".repeat(257)));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new FailureRecord(
                                UUID.randomUUID(),
                                java.time.Instant.now(),
                                Category.POLICY_DENIED,
                                Stage.POLICY_EVALUATION,
                                FailureRecord.Boundary.UNKNOWN,
                                null,
                                null,
                                null,
                                null,
                                null,
                                0,
                                "secret-not-a-fingerprint",
                                null));
        assertThrows(
                UnsupportedOperationException.class, () -> diagnostics.snapshot().counts().clear());
    }

    @Test
    void remoteDetectorFailuresAreNotMisclassifiedAsPolicyDenials() {
        var diagnostics = new FailureDiagnostics(16);
        for (String reason :
                List.of("request", "interrupted", "auth", "http", "protocol", "transport")) {
            var record =
                    diagnostics.record(
                            new SecurityBlockedException("detector-remote-" + reason),
                            Stage.POLICY_EVALUATION,
                            SecurityEvent.Phase.MODEL_INPUT,
                            null,
                            null,
                            null);
            assertEquals(Category.DETECTOR_FAILURE, record.category());
        }
        assertEquals(
                Category.TIMEOUT,
                diagnostics
                        .record(
                                new SecurityBlockedException("detector-remote-timeout"),
                                Stage.POLICY_EVALUATION,
                                null,
                                null,
                                null,
                                null)
                        .category());
        assertEquals(
                Category.CAPACITY_LIMIT,
                diagnostics
                        .record(
                                new SecurityBlockedException("detector-remote-capacity"),
                                Stage.POLICY_EVALUATION,
                                null,
                                null,
                                null,
                                null)
                        .category());
        assertEquals(
                Category.POLICY_DENIED,
                diagnostics
                        .record(
                                new SecurityBlockedException("remote-denied"),
                                Stage.POLICY_EVALUATION,
                                null,
                                null,
                                null,
                                null)
                        .category());
        assertEquals(
                Category.TIMEOUT,
                diagnostics
                        .record(
                                new java.net.http.HttpTimeoutException("secret"),
                                Stage.MCP_EXECUTION,
                                null,
                                null,
                                null,
                                null)
                        .category());
    }

    private static long total(FailureDiagnostics diagnostics) {
        return diagnostics.snapshot().counts().stream()
                .mapToLong(FailureDiagnostics.Count::total)
                .sum();
    }
}
