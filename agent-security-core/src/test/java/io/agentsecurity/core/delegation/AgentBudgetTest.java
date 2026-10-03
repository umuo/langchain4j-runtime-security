package io.agentsecurity.core.delegation;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class AgentBudgetTest {
    private static final Duration TTL = Duration.ofMinutes(1);
    private static final AgentGrant GRANT = AgentGrant.tools(Set.of("read"), Set.of("lookup"));
    private static final SecurityContext USER =
            SecurityContext.authenticated("tenant", "user", Set.of("read"));

    private AgentRuntime runtime() {
        return new AgentRuntime(
                List.of(new AgentDefinition("agent", GRANT, Set.of("agent"))),
                AgentRuntimeLimits.defaults(),
                (event, decision) -> {});
    }

    private AgentInvocation root(AgentRuntime runtime, int invocations, long checks) {
        return runtime.startRoot(
                "agent", USER, GRANT, TTL, new AgentBudgetLimits(invocations, checks));
    }

    private SecurityEvent event(AgentInvocation invocation, SecurityEvent.Phase phase) {
        return new SecurityEvent(UUID.randomUUID(), phase, "lookup", "{}", invocation.context());
    }

    @Test
    void finishedChildrenDoNotRefundAndExhaustionRevokesWholeTree() throws Exception {
        try (var runtime = runtime();
                var root = root(runtime, 3, 10)) {
            root.call(
                    () -> {
                        var first = runtime.delegate("agent", GRANT, TTL);
                        first.call(() -> null);
                        var sibling = runtime.delegate("agent", GRANT, TTL);
                        assertEquals(3, sibling.budgetSnapshot().invocations());
                        assertEquals(
                                "agent-budget-invocations",
                                assertThrows(
                                                SecurityBlockedException.class,
                                                () -> runtime.delegate("agent", GRANT, TTL))
                                        .ruleId());
                        assertEquals(AgentEndReason.BUDGET_EXHAUSTED, root.endReason());
                        assertEquals(AgentEndReason.PARENT_REVOKED, sibling.endReason());
                        return null;
                    });
            fail("terminated root must not deliver success");
        } catch (SecurityBlockedException expected) {
            assertEquals("agent-invocation-inactive", expected.ruleId());
        }
    }

    @Test
    void inputsChargeOnceOutputsDoNotChargeAndRootsAreIsolated() throws Exception {
        try (var runtime = runtime();
                var first = root(runtime, 10, 1);
                var second = root(runtime, 10, 1);
                var engine = new PolicyEngine(List.of(), (e, d) -> {})) {
            engine.check(event(first, SecurityEvent.Phase.TOOL_INPUT));
            engine.check(event(first, SecurityEvent.Phase.TOOL_OUTPUT));
            assertEquals(1, first.budgetSnapshot().protectedChecks());
            assertEquals(
                    "agent-budget-checks",
                    assertThrows(
                                    SecurityBlockedException.class,
                                    () ->
                                            engine.check(
                                                    event(first, SecurityEvent.Phase.MODEL_INPUT)))
                            .ruleId());
            engine.check(event(second, SecurityEvent.Phase.TOOL_INPUT));
            assertNull(second.endReason());
            assertEquals(0, second.budgetSnapshot().invocations() - 1);
        }
    }

    @Test
    void parallelSiblingsCannotOverspendLastCheck() throws Exception {
        try (var runtime = runtime();
                var root = root(runtime, 100, 7);
                var engine = new PolicyEngine(List.of(), (e, d) -> {})) {
            var children = new ArrayList<AgentInvocation>();
            try (var scope = SecurityContexts.open(root.context())) {
                for (int i = 0; i < 20; i++) {
                    children.add(runtime.delegate("agent", GRANT, TTL));
                }
            }
            var ready = new CountDownLatch(20);
            var go = new CountDownLatch(1);
            var allowed = new AtomicInteger();
            var executor = Executors.newFixedThreadPool(20);
            try {
                var futures = new ArrayList<Future<?>>();
                for (var child : children) {
                    futures.add(
                            executor.submit(
                                    () -> {
                                        ready.countDown();
                                        try {
                                            assertTrue(go.await(5, TimeUnit.SECONDS));
                                            engine.check(
                                                    event(child, SecurityEvent.Phase.TOOL_INPUT));
                                            allowed.incrementAndGet();
                                        } catch (SecurityBlockedException denied) {
                                            // 并发撤销也可能在最终授权复检处拒绝已经扣费的检查。
                                        } catch (InterruptedException interrupted) {
                                            Thread.currentThread().interrupt();
                                            throw new AssertionError(interrupted);
                                        }
                                    }));
                }
                assertTrue(ready.await(5, TimeUnit.SECONDS));
                go.countDown();
                for (var future : futures) {
                    future.get(10, TimeUnit.SECONDS);
                }
                assertTrue(allowed.get() <= 7);
                assertEquals(7, root.budgetSnapshot().protectedChecks());
                assertEquals(AgentEndReason.BUDGET_EXHAUSTED, root.endReason());
                assertEquals(0, runtime.snapshot().activeInvocations());
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void deniedDetectorAttemptsStillConsumeBudget() {
        try (var runtime = runtime();
                var root = root(runtime, 10, 1);
                var engine =
                        new PolicyEngine(
                                List.of(e -> Decision.deny("custom-deny")), (e, d) -> {})) {
            assertEquals(
                    "custom-deny",
                    assertThrows(
                                    SecurityBlockedException.class,
                                    () -> engine.check(event(root, SecurityEvent.Phase.TOOL_INPUT)))
                            .ruleId());
            assertEquals(
                    "agent-budget-checks",
                    assertThrows(
                                    SecurityBlockedException.class,
                                    () -> engine.check(event(root, SecurityEvent.Phase.TOOL_INPUT)))
                            .ruleId());
        }
    }

    @Test
    void queuedCancellationSkipsTaskAndRunningCancellationRejectsResult() throws Exception {
        try (var runtime = runtime();
                var root = root(runtime, 10, 10)) {
            var queue = new ArrayList<Runnable>();
            var future =
                    root.submit(
                            queue::add,
                            () -> {
                                fail("cancelled task entered");
                                return null;
                            });
            root.cancel();
            queue.get(0).run();
            assertInstanceOf(
                    SecurityBlockedException.class,
                    assertThrows(CompletionException.class, future::join).getCause());
            assertEquals(AgentEndReason.CANCELLED, root.endReason());
        }
        try (var runtime = runtime();
                var root = root(runtime, 10, 10)) {
            assertEquals(
                    "agent-invocation-inactive",
                    assertThrows(
                                    SecurityBlockedException.class,
                                    () ->
                                            root.call(
                                                    () -> {
                                                        root.cancel();
                                                        return "must not escape";
                                                    }))
                            .ruleId());
        }
    }

    @Test
    void reusedEventIdDoesNotBypassBudget() {
        try (var runtime = runtime();
                var root = root(runtime, 10, 1);
                var engine = new PolicyEngine(List.of(), (e, d) -> {})) {
            var event = event(root, SecurityEvent.Phase.MODEL_INPUT);
            engine.check(event);
            var denied = assertThrows(SecurityBlockedException.class, () -> engine.check(event));
            assertEquals(
                    io.agentsecurity.core.diagnostics.FailureRecord.Category.CAPACITY_LIMIT,
                    denied.diagnostic().category());
            assertEquals(1, root.budgetSnapshot().protectedChecks());
        }
    }

    @Test
    void concurrentCancellationRejectsAlreadyRunningResult() throws Exception {
        try (var runtime = runtime();
                var root = root(runtime, 10, 10)) {
            var entered = new CountDownLatch(1);
            var release = new CountDownLatch(1);
            var executor = Executors.newSingleThreadExecutor();
            try {
                var future =
                        root.submit(
                                executor,
                                () -> {
                                    entered.countDown();
                                    assertTrue(release.await(5, TimeUnit.SECONDS));
                                    return "must not escape";
                                });
                assertTrue(entered.await(5, TimeUnit.SECONDS));
                root.cancel();
                release.countDown();
                var error =
                        assertThrows(
                                ExecutionException.class, () -> future.get(5, TimeUnit.SECONDS));
                assertInstanceOf(SecurityBlockedException.class, error.getCause());
                assertEquals(AgentEndReason.CANCELLED, root.endReason());
            } finally {
                release.countDown();
                executor.shutdownNow();
            }
        }
    }

    @Test
    void subtreeCancellationLeavesIndependentRootUsable() {
        try (var runtime = runtime();
                var root = root(runtime, 10, 10);
                var other = root(runtime, 10, 10);
                var engine = new PolicyEngine(List.of(), (e, d) -> {})) {
            var queue = new ArrayList<Runnable>();
            CompletableFuture<String> future;
            AgentInvocation child;
            try (var scope = SecurityContexts.open(root.context())) {
                child = runtime.delegate("agent", GRANT, TTL);
                future =
                        child.submit(
                                queue::add,
                                () -> {
                                    fail("child entered after cancellation");
                                    return "bad";
                                });
            }
            root.cancel();
            assertEquals(AgentEndReason.PARENT_REVOKED, child.endReason());
            queue.get(0).run();
            assertThrows(CompletionException.class, future::join);
            engine.check(event(other, SecurityEvent.Phase.MODEL_INPUT));
            assertNull(other.endReason());
        }
    }

    @Test
    void budgetTerminationAuditFailureInvalidatesOtherRoots() {
        var rejectTermination = new java.util.concurrent.atomic.AtomicBoolean();
        try (var runtime =
                        new AgentRuntime(
                                List.of(new AgentDefinition("agent", GRANT, Set.of("agent"))),
                                AgentRuntimeLimits.defaults(),
                                (e, d) -> {
                                    if (rejectTermination.get()) {
                                        throw new IllegalStateException("audit unavailable");
                                    }
                                });
                var root = root(runtime, 10, 1);
                var other = root(runtime, 10, 10);
                var engine = new PolicyEngine(List.of(), (e, d) -> {})) {
            engine.check(event(root, SecurityEvent.Phase.MODEL_INPUT));
            rejectTermination.set(true);
            assertEquals(
                    "agent-audit-error",
                    assertThrows(
                                    SecurityBlockedException.class,
                                    () ->
                                            engine.check(
                                                    event(root, SecurityEvent.Phase.MODEL_INPUT)))
                            .ruleId());
            assertEquals(AgentEndReason.BUDGET_EXHAUSTED, root.endReason());
            assertEquals(AgentEndReason.AUDIT_FAILED, other.endReason());
            assertEquals(0, runtime.snapshot().activeInvocations());
        }
    }

    @Test
    void invalidBudgetsFailBeforeRegistration() {
        assertThrows(IllegalArgumentException.class, () -> new AgentBudgetLimits(0, 1));
        assertThrows(IllegalArgumentException.class, () -> new AgentBudgetLimits(1, 0));
        assertThrows(IllegalArgumentException.class, () -> new AgentBudgetLimits(10001, 1));
        assertThrows(IllegalArgumentException.class, () -> new AgentBudgetLimits(1, 1000001));
    }
}
