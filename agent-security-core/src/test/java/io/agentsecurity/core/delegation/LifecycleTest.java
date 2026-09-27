package io.agentsecurity.core.delegation;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.*;
import io.agentsecurity.core.telemetry.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;

/** 验证逐节点终止、原因互斥、后台过期和一致采样，不从可丢失的遥测反推权限状态。 */
class LifecycleTest {
    private static final AgentGrant GRANT = AgentGrant.tools(Set.of("read"), Set.of("lookup"));
    private static final SecurityContext USER =
            SecurityContext.authenticated("tenant", "user", Set.of("read"));
    private static final Duration TTL = Duration.ofSeconds(10);

    private AgentRuntime runtime(SecurityTelemetry telemetry) {
        return new AgentRuntime(
                List.of(new AgentDefinition("agent", GRANT, Set.of("agent"))),
                AgentRuntimeLimits.defaults(),
                (e, d) -> {},
                telemetry);
    }

    private static void await(BooleanSupplier ready) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(3).toNanos();
        while (!ready.getAsBoolean() && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertTrue(ready.getAsBoolean());
    }

    @Test
    void parentCompletionEndsEveryOutstandingDescendantOnce() throws Exception {
        var telemetry = new SecurityTelemetry(30, 1);
        try (var runtime = runtime(telemetry)) {
            var root = runtime.startRoot("agent", USER, GRANT, TTL);
            var children = new ArrayList<AgentInvocation>();
            root.call(
                    () -> {
                        var child = runtime.delegate("agent", GRANT, TTL);
                        children.add(child);
                        try (var scope = SecurityContexts.open(child.context())) {
                            children.add(runtime.delegate("agent", GRANT, TTL));
                        }
                        assertEquals(3, runtime.snapshot().activeInvocations());
                        assertEquals(2, runtime.snapshot().maxDepth());
                        return null;
                    });
            assertEquals(AgentEndReason.COMPLETED, root.endReason());
            children.forEach(
                    child -> assertEquals(AgentEndReason.PARENT_FINISHED, child.endReason()));
            root.revoke();
            children.forEach(AgentInvocation::close);
            assertEquals(0, runtime.snapshot().activeInvocations());
            assertEquals(2L, runtime.snapshot().ended().get(AgentEndReason.PARENT_FINISHED));
            var records =
                    telemetry.drain(30).stream()
                            .filter(record -> record.endReason() != null)
                            .toList();
            assertEquals(3, records.size());
            assertEquals(3, records.stream().map(TelemetryRecord::invocationId).distinct().count());
            assertTrue(records.stream().allMatch(record -> record.lifetimeNanos() > 0));
        }
    }

    @Test
    void taskFailureIsPreservedAndDescendantsAreRevoked() throws Exception {
        try (var runtime = runtime(SecurityTelemetry.disabled())) {
            var root = runtime.startRoot("agent", USER, GRANT, TTL);
            var child = new AtomicReference<AgentInvocation>();
            var original = new IllegalArgumentException("private task failure");
            assertSame(
                    original,
                    assertThrows(
                            IllegalArgumentException.class,
                            () ->
                                    root.call(
                                            () -> {
                                                child.set(runtime.delegate("agent", GRANT, TTL));
                                                throw original;
                                            })));
            assertEquals(AgentEndReason.FAILED, root.endReason());
            assertEquals(AgentEndReason.PARENT_REVOKED, child.get().endReason());
        }
    }

    @Test
    void cancellationAndExecutorRejectionHaveDistinctReasons() throws Exception {
        try (var runtime = runtime(SecurityTelemetry.disabled())) {
            var root = runtime.startRoot("agent", USER, GRANT, TTL);
            root.call(
                    () -> {
                        var child = runtime.delegate("agent", GRANT, TTL);
                        var queue = new AtomicReference<Runnable>();
                        var future =
                                child.submit(
                                        queue::set,
                                        () -> {
                                            fail("Cancelled task executed");
                                            return null;
                                        });
                        future.cancel(false);
                        queue.get().run();
                        assertEquals(AgentEndReason.CANCELLED, child.endReason());
                        var rejected = runtime.delegate("agent", GRANT, TTL);
                        var result =
                                rejected.submit(
                                        task -> {
                                            throw new RejectedExecutionException();
                                        },
                                        () -> null);
                        assertTrue(result.isCompletedExceptionally());
                        assertEquals(AgentEndReason.EXECUTOR_REJECTED, rejected.endReason());
                        return null;
                    });
        }
    }

    @Test
    void expirySweeperEmitsTerminalRecordsWithoutAnotherBusinessCall() throws Exception {
        var telemetry = new SecurityTelemetry(20, 1);
        try (var runtime = runtime(telemetry)) {
            var root = runtime.startRoot("agent", USER, GRANT, Duration.ofMillis(200));
            AgentInvocation child;
            try (var scope = SecurityContexts.open(root.context())) {
                child = runtime.delegate("agent", GRANT, TTL);
            }
            await(
                    () ->
                            root.endReason() == AgentEndReason.EXPIRED
                                    && child.endReason() == AgentEndReason.EXPIRED);
            assertEquals(0, runtime.snapshot().activeInvocations());
            assertEquals(2L, runtime.snapshot().ended().get(AgentEndReason.EXPIRED));
            assertEquals(0, runtime.expireNow());
            assertEquals(
                    2,
                    telemetry.drain(20).stream()
                            .filter(r -> r.phase() == SecurityEvent.Phase.AGENT_EXPIRE)
                            .count());
        }
    }

    @Test
    void runtimeCloseAccountsForEveryLiveNode() throws Exception {
        var runtime = runtime(SecurityTelemetry.disabled());
        var root = runtime.startRoot("agent", USER, GRANT, TTL);
        AgentInvocation child;
        try (var scope = SecurityContexts.open(root.context())) {
            child = runtime.delegate("agent", GRANT, TTL);
        }
        runtime.close();
        runtime.close();
        assertEquals(AgentEndReason.RUNTIME_CLOSED, root.endReason());
        assertEquals(AgentEndReason.RUNTIME_CLOSED, child.endReason());
        assertEquals(2L, runtime.snapshot().ended().get(AgentEndReason.RUNTIME_CLOSED));
    }

    @Test
    void competingCompletionAndRevocationOnlyProduceOneTerminalEvent() throws Exception {
        var telemetry = new SecurityTelemetry(20, 1);
        var pool = Executors.newFixedThreadPool(2);
        try (var runtime = runtime(telemetry)) {
            var root = runtime.startRoot("agent", USER, GRANT, TTL);
            var entered = new CountDownLatch(1);
            var release = new CountDownLatch(1);
            var result =
                    root.submit(
                            pool,
                            () -> {
                                entered.countDown();
                                release.await();
                                return "done";
                            });
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            var revoke = pool.submit(root::revoke);
            release.countDown();
            revoke.get();
            result.get();
            assertTrue(
                    Set.of(AgentEndReason.REVOKED, AgentEndReason.COMPLETED)
                            .contains(root.endReason()));
            assertEquals(
                    1, telemetry.drain(20).stream().filter(r -> r.endReason() != null).count());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void auditFailureCannotLeaveAnotherRootOrDescendantActive() throws Exception {
        var terminal = new CopyOnWriteArrayList<String>();
        var telemetry = new SecurityTelemetry(30, 1);
        try (var runtime =
                new AgentRuntime(
                        List.of(new AgentDefinition("agent", GRANT, Set.of("agent"))),
                        AgentRuntimeLimits.defaults(),
                        (e, d) -> {
                            if (!d.ruleId().equals("allow")) {
                                terminal.add(d.ruleId());
                                throw new IllegalStateException();
                            }
                        },
                        telemetry)) {
            var root = runtime.startRoot("agent", USER, GRANT, TTL);
            var other = runtime.startRoot("agent", USER, GRANT, TTL);
            AgentInvocation child;
            try (var scope = SecurityContexts.open(root.context())) {
                child = runtime.delegate("agent", GRANT, TTL);
            }
            assertThrows(SecurityBlockedException.class, root::revoke);
            assertEquals(AgentEndReason.REVOKED, root.endReason());
            assertEquals(AgentEndReason.PARENT_REVOKED, child.endReason());
            assertEquals(AgentEndReason.AUDIT_FAILED, other.endReason());
            assertEquals(0, runtime.snapshot().activeInvocations());
            var ends = telemetry.drain(30).stream().filter(r -> r.endReason() != null).toList();
            assertEquals(3, ends.size());
            assertTrue(
                    ends.stream()
                            .allMatch(r -> r.outcome() == SecurityTelemetry.Outcome.AUDIT_FAILURE));
            assertEquals(1, terminal.size()); // 有界审计进入持续失败态，其余只尝试、不重复调用后端。
        }
    }

    @Test
    void allEventsInOneRunUseTheSameSamplingDecision() {
        var telemetry = new SecurityTelemetry(20, 2);
        for (int run = 0; run < 2; run++) {
            var identity = new SecurityContext(new UUID(0, run), "tenant", "user", Set.of());
            for (int event = 0; event < 5; event++) {
                telemetry.record(
                        new SecurityEvent(
                                UUID.randomUUID(),
                                SecurityEvent.Phase.TOOL_INPUT,
                                "lookup",
                                "",
                                identity),
                        SecurityTelemetry.Outcome.ALLOW,
                        1);
            }
        }
        var records = telemetry.drain(20);
        assertEquals(5, records.size());
        assertTrue(records.stream().allMatch(r -> r.runId().equals(new UUID(0, 0))));
        assertEquals(
                10,
                telemetry.snapshot().metrics().stream()
                        .mapToLong(SecurityTelemetry.Metric::count)
                        .sum());
    }
}
