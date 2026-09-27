package io.agentsecurity.core.delegation;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AgentRuntimeTest {
    private static final Duration TTL = Duration.ofMinutes(1);
    private static final SecurityContext USER =
            SecurityContext.authenticated("tenant-a", "user-a", Set.of("read", "write"));
    private static final AgentGrant FULL =
            AgentGrant.tools(Set.of("read", "write"), Set.of("lookup", "delete"));
    private static final AgentGrant READ = AgentGrant.tools(Set.of("read"), Set.of("lookup"));

    private AgentRuntime runtime() {
        return new AgentRuntime(
                List.of(
                        new AgentDefinition("planner", FULL, Set.of("reader", "planner")),
                        new AgentDefinition("reader", READ, Set.of())),
                AgentRuntimeLimits.defaults(),
                (event, decision) -> {});
    }

    private PolicyEngine engine() {
        return new PolicyEngine(List.of(), (event, decision) -> {});
    }

    private SecurityEvent event(SecurityContext context, String tool) {
        return new SecurityEvent(
                UUID.randomUUID(), SecurityEvent.Phase.TOOL_INPUT, tool, "{}", context);
    }

    private void denied(String rule, org.junit.jupiter.api.function.Executable action) {
        assertEquals(rule, assertThrows(SecurityBlockedException.class, action).ruleId());
    }

    @Test
    void childLinksAreDistinctAndGrantsCanOnlyShrink() throws Exception {
        try (var runtime = runtime();
                var root = runtime.startRoot("planner", USER, FULL, TTL);
                var engine = engine()) {
            root.call(
                    () -> {
                        try (var child = runtime.delegate("reader", FULL, TTL);
                                var sibling = runtime.delegate("reader", FULL, TTL)) {
                            assertEquals(root.invocationId(), child.parentInvocationId());
                            assertEquals(root.rootRunId(), child.rootRunId());
                            assertNotEquals(child.invocationId(), sibling.invocationId());
                            assertNotEquals(child.delegationId(), sibling.delegationId());
                            assertEquals(READ, child.grant());
                            child.call(
                                    () -> {
                                        engine.check(event(SecurityContexts.current(), "lookup"));
                                        denied(
                                                "agent-tool-denied",
                                                () ->
                                                        engine.check(
                                                                event(
                                                                        SecurityContexts.current(),
                                                                        "delete")));
                                        return null;
                                    });
                            assertSame(root.context(), SecurityContexts.current());
                            engine.check(event(sibling.context(), "lookup"));
                        }
                        return null;
                    });
            assertNull(SecurityContexts.current());
        }
    }

    @Test
    void parentAndUserPermissionsBoundRootAndGrandchildren() throws Exception {
        var identity = SecurityContext.authenticated("tenant-a", "reader", Set.of("read"));
        try (var runtime = runtime();
                var root = runtime.startRoot("planner", identity, FULL, TTL)) {
            assertEquals(Set.of("read"), root.context().permissions());
            root.call(
                    () -> {
                        try (var child = runtime.delegate("planner", READ, TTL)) {
                            child.call(
                                    () -> {
                                        try (var grandchild =
                                                runtime.delegate("reader", FULL, TTL)) {
                                            assertEquals(READ, grandchild.grant());
                                            assertEquals(
                                                    child.invocationId(),
                                                    grandchild.parentInvocationId());
                                        }
                                        return null;
                                    });
                        }
                        return null;
                    });
        }
    }

    @Test
    void cannotDelegateWithoutParentOrCallAnUnregisteredChildOrCreateNestedRoot() throws Exception {
        try (var runtime = runtime();
                var root = runtime.startRoot("reader", USER, READ, TTL)) {
            denied("agent-parent-required", () -> runtime.delegate("reader", READ, TTL));
            root.call(
                    () -> {
                        denied("agent-child-denied", () -> runtime.delegate("planner", FULL, TTL));
                        denied(
                                "agent-root-from-child",
                                () -> runtime.startRoot("planner", USER, FULL, TTL));
                        return null;
                    });
        }
    }

    @Test
    void tamperedPermissionsIdentityAndRunAreRejected() {
        try (var runtime = runtime();
                var root = runtime.startRoot("reader", USER, READ, TTL);
                var engine = engine()) {
            var original = root.context();
            for (var spoofed :
                    List.of(
                            new SecurityContext(
                                    original.runId(),
                                    "tenant-b",
                                    original.principalId(),
                                    original.permissions(),
                                    root),
                            new SecurityContext(
                                    original.runId(),
                                    original.tenantId(),
                                    "other",
                                    original.permissions(),
                                    root),
                            new SecurityContext(
                                    original.runId(),
                                    original.tenantId(),
                                    original.principalId(),
                                    Set.of("write"),
                                    root),
                            new SecurityContext(
                                    UUID.randomUUID(),
                                    original.tenantId(),
                                    original.principalId(),
                                    original.permissions(),
                                    root))) {
                denied("agent-context-mismatch", () -> engine.check(event(spoofed, "lookup")));
            }
        }
    }

    @Test
    void foreignRuntimeCannotUseParentHandle() throws Exception {
        try (var runtime = runtime();
                var other = runtime();
                var root = runtime.startRoot("planner", USER, FULL, TTL)) {
            root.call(
                    () -> {
                        denied("agent-context-mismatch", () -> other.delegate("reader", READ, TTL));
                        return null;
                    });
        }
    }

    @Test
    void revokedParentInvalidatesWholeTreeButNotOtherRoot() throws Exception {
        try (var runtime = runtime();
                var root = runtime.startRoot("planner", USER, FULL, TTL);
                var other = runtime.startRoot("reader", USER, READ, TTL);
                var engine = engine()) {
            root.call(
                    () -> {
                        var child = runtime.delegate("reader", READ, TTL);
                        root.revoke();
                        denied(
                                "agent-invocation-inactive",
                                () -> engine.check(event(child.context(), "lookup")));
                        engine.check(event(other.context(), "lookup"));
                        return null;
                    });
        }
    }

    @Test
    void expirationCannotBeExtendedByDelegation() throws Exception {
        try (var runtime = runtime();
                var root = runtime.startRoot("planner", USER, FULL, Duration.ofMillis(150));
                var engine = engine()) {
            try (var scope = SecurityContexts.open(root.context())) {
                var child = runtime.delegate("reader", READ, TTL);
                Thread.sleep(180);
                denied(
                        "agent-invocation-expired",
                        () -> engine.check(event(child.context(), "lookup")));
            }
        }
    }

    @Test
    void capacityAndDepthAreBoundedAndCompletionReclaimsCapacity() throws Exception {
        try (var runtime =
                        new AgentRuntime(
                                List.of(new AgentDefinition("planner", FULL, Set.of("planner"))),
                                new AgentRuntimeLimits(2, 1, TTL),
                                (e, d) -> {});
                var root = runtime.startRoot("planner", USER, FULL, TTL)) {
            root.call(
                    () -> {
                        try (var child = runtime.delegate("planner", READ, TTL)) {
                            denied("agent-capacity", () -> runtime.delegate("planner", READ, TTL));
                            child.call(
                                    () -> {
                                        denied(
                                                "agent-depth-limit",
                                                () -> runtime.delegate("planner", READ, TTL));
                                        return null;
                                    });
                        }
                        try (var replacement = runtime.delegate("planner", READ, TTL)) {
                            assertNotNull(replacement);
                        }
                        return null;
                    });
        }
    }

    @Test
    void completedInvocationCannotRunAgainAndTaskFailureRestoresIdentity() {
        try (var runtime = runtime();
                var root = runtime.startRoot("reader", USER, READ, TTL);
                var scope = SecurityContexts.open(USER)) {
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            root.call(
                                    () -> {
                                        throw new IllegalArgumentException();
                                    }));
            assertSame(USER, SecurityContexts.current());
            denied("agent-invocation-inactive", () -> root.call(() -> null));
        }
    }

    @Test
    void queuedCancellationAndExecutorRejectionNeverRunTask() {
        try (var runtime = runtime();
                var root = runtime.startRoot("reader", USER, READ, TTL);
                var engine = engine()) {
            var queued = new ArrayList<Runnable>();
            var calls = new AtomicInteger();
            var future = root.submit(queued::add, calls::incrementAndGet);
            future.cancel(false);
            queued.get(0).run();
            assertEquals(0, calls.get());
            denied(
                    "agent-invocation-inactive",
                    () -> engine.check(event(root.context(), "lookup")));
            var rejected = runtime.startRoot("reader", USER, READ, TTL);
            assertTrue(
                    rejected.submit(
                                    task -> {
                                        throw new RejectedExecutionException();
                                    },
                                    calls::incrementAndGet)
                            .isCompletedExceptionally());
            denied(
                    "agent-invocation-inactive",
                    () -> engine.check(event(rejected.context(), "lookup")));
        }
    }

    @Test
    void asynchronousChildrenKeepDistinctIdentitiesAndRestoreWorkerContext() throws Exception {
        try (var runtime = runtime();
                var root = runtime.startRoot("planner", USER, FULL, TTL);
                var engine = engine()) {
            var pool = Executors.newFixedThreadPool(2);
            try {
                root.call(
                        () -> {
                            var first = runtime.delegate("reader", READ, TTL);
                            var second = runtime.delegate("reader", READ, TTL);
                            var bothStarted = new CountDownLatch(2);
                            var futures =
                                    List.of(first, second).stream()
                                            .map(
                                                    child ->
                                                            child.submit(
                                                                    pool,
                                                                    () -> {
                                                                        bothStarted.countDown();
                                                                        assertTrue(
                                                                                bothStarted.await(
                                                                                        5,
                                                                                        TimeUnit
                                                                                                .SECONDS));
                                                                        assertSame(
                                                                                child.context(),
                                                                                SecurityContexts
                                                                                        .current());
                                                                        engine.check(
                                                                                event(
                                                                                        SecurityContexts
                                                                                                .current(),
                                                                                        "lookup"));
                                                                        return SecurityContexts
                                                                                .current()
                                                                                .invocation()
                                                                                .invocationId();
                                                                    }))
                                            .toList();
                            assertNotEquals(
                                    futures.get(0).get(5, TimeUnit.SECONDS),
                                    futures.get(1).get(5, TimeUnit.SECONDS));
                            assertNull(
                                    pool.submit(SecurityContexts::current)
                                            .get(5, TimeUnit.SECONDS));
                            return null;
                        });
            } finally {
                pool.shutdownNow();
            }
        }
    }

    @Test
    void revocationDuringDetectorEvaluationIsRecheckedBeforeAllowing() {
        try (var runtime = runtime();
                var root = runtime.startRoot("reader", USER, READ, TTL);
                var engine =
                        new PolicyEngine(
                                List.of(
                                        e -> {
                                            root.revoke();
                                            return Decision.allow();
                                        }),
                                (e, d) -> {})) {
            denied(
                    "agent-invocation-inactive",
                    () -> engine.check(event(root.context(), "lookup")));
        }
    }

    @Test
    void lifecycleAuditFailureBlocksAllOutstandingInvocations() {
        var count = new AtomicInteger();
        try (var runtime =
                        new AgentRuntime(
                                List.of(new AgentDefinition("reader", READ, Set.of())),
                                AgentRuntimeLimits.defaults(),
                                (e, d) -> {
                                    if (count.incrementAndGet() == 2) {
                                        throw new IllegalStateException();
                                    }
                                });
                var root = runtime.startRoot("reader", USER, READ, TTL);
                var engine = engine()) {
            denied("agent-audit-error", () -> runtime.startRoot("reader", USER, READ, TTL));
            denied("agent-audit-error", () -> engine.check(event(root.context(), "lookup")));
            // 移除登记会再次尝试审计，仍然拒绝；运行时最终关闭必须释放资源。
            denied("agent-audit-error", root::close);
        }
    }

    @Test
    void memoryAndRetrieverAllowListsAreEnforcedIndependently() {
        var resource = new ResourceRef("memory:string", "session-a");
        var grant =
                new AgentGrant(
                        Set.of("read"), Set.of(), Set.of("trusted.Retriever"), Set.of(resource));
        try (var runtime =
                        new AgentRuntime(
                                List.of(new AgentDefinition("reader", grant, Set.of())),
                                AgentRuntimeLimits.defaults(),
                                (e, d) -> {});
                var root = runtime.startRoot("reader", USER, grant, TTL);
                var engine = engine()) {
            engine.check(
                    new SecurityEvent(
                            UUID.randomUUID(),
                            SecurityEvent.Phase.MEMORY_READ_INPUT,
                            "memory#get",
                            "",
                            root.context(),
                            resource));
            denied(
                    "agent-memory-denied",
                    () ->
                            engine.check(
                                    new SecurityEvent(
                                            UUID.randomUUID(),
                                            SecurityEvent.Phase.MEMORY_DELETE,
                                            "memory#delete",
                                            "",
                                            root.context(),
                                            new ResourceRef("memory:string", "session-b"))));
            denied(
                    "agent-retriever-denied",
                    () ->
                            engine.check(
                                    new SecurityEvent(
                                            UUID.randomUUID(),
                                            SecurityEvent.Phase.RETRIEVAL_INPUT,
                                            "other.Retriever",
                                            "",
                                            root.context())));
        }
    }

    @Test
    void requiredModeRejectsMissingDelegationButLegacyModeStillWorks() {
        var properties = new Properties();
        properties.setProperty("agent.context.required", "true");
        try (var engine = new PolicyEngine(List.of(new LocalPolicy(properties)), (e, d) -> {});
                var legacy = engine()) {
            denied("missing-agent-context", () -> engine.check(event(USER, "lookup")));
            legacy.check(event(USER, "lookup"));
        }
        properties.setProperty("agent.context.required", "yes");
        assertThrows(IllegalArgumentException.class, () -> new LocalPolicy(properties));
    }

    @Test
    void lifecycleAndDecisionAuditCanReconstructParentageWithoutPayload(@TempDir Path dir)
            throws Exception {
        var events = new CopyOnWriteArrayList<SecurityEvent>();
        var path = dir.resolve("audit.jsonl");
        try (var file = new FileAuditSink(path, 100000, 1, false, "delegation-v1");
                var runtime =
                        new AgentRuntime(
                                List.of(
                                        new AgentDefinition("planner", FULL, Set.of("reader")),
                                        new AgentDefinition("reader", READ, Set.of())),
                                AgentRuntimeLimits.defaults(),
                                (e, d) -> {
                                    events.add(e);
                                    file.accept(e, d);
                                });
                var root = runtime.startRoot("planner", USER, FULL, TTL);
                var engine = new PolicyEngine(List.of(), file)) {
            root.call(
                    () -> {
                        var child = runtime.delegate("reader", READ, TTL);
                        child.call(
                                () -> {
                                    engine.check(event(SecurityContexts.current(), "lookup"));
                                    return null;
                                });
                        return null;
                    });
        }
        var lines = Files.readAllLines(path);
        assertEquals(5, lines.size());
        assertTrue(
                lines.stream()
                        .allMatch(
                                l ->
                                        l.contains("\"schemaVersion\":3")
                                                && l.contains("\"invocationId\":\"")));
        assertFalse(String.join("", lines).contains("tenant-a"));
        assertFalse(String.join("", lines).contains("user-a"));
        assertEquals(
                List.of(
                        SecurityEvent.Phase.AGENT_START,
                        SecurityEvent.Phase.AGENT_DELEGATE,
                        SecurityEvent.Phase.AGENT_FINISH,
                        SecurityEvent.Phase.AGENT_FINISH),
                events.stream().map(SecurityEvent::phase).toList());
        assertEquals(
                events.get(0).context().invocation().invocationId(),
                events.get(1).context().invocation().parentInvocationId());
    }
}
