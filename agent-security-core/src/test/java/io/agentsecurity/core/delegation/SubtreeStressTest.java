package io.agentsecurity.core.delegation;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.*;
import io.agentsecurity.core.telemetry.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;

/** 有界大子树验证：整批失效发生在逐节点慢审计之前，每个执行只终止一次。 */
class SubtreeStressTest {
    @Test
    void revokeWideSubtreeInvalidatesAllNodesBeforeSlowAuditAndPreservesOtherRoot()
            throws Exception {
        int size = 1024;
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var telemetry = new SecurityTelemetry(4096, 1);
        var grant = AgentGrant.tools(Set.of("read"), Set.of("lookup"));
        var user = SecurityContext.authenticated("tenant", "user", Set.of("read"));
        var pool = Executors.newSingleThreadExecutor();
        try (var runtime =
                new AgentRuntime(
                        List.of(new AgentDefinition("agent", grant, Set.of("agent"))),
                        new AgentRuntimeLimits(2048, 8, Duration.ofMinutes(1)),
                        (event, decision) -> {
                            if (decision.ruleId().equals("agent-end-revoked")) {
                                entered.countDown();
                                try {
                                    if (!release.await(800, TimeUnit.MILLISECONDS)) {
                                        throw new IllegalStateException("Test audit timeout");
                                    }
                                } catch (InterruptedException error) {
                                    Thread.currentThread().interrupt();
                                    throw new IllegalStateException(error);
                                }
                            }
                        },
                        telemetry)) {
            var root = runtime.startRoot("agent", user, grant, Duration.ofMinutes(1));
            var other = runtime.startRoot("agent", user, grant, Duration.ofMinutes(1));
            var descendants = new ArrayList<AgentInvocation>();
            try (var scope = SecurityContexts.open(root.context())) {
                for (int i = 1; i < size; i++) {
                    descendants.add(runtime.delegate("agent", grant, Duration.ofMinutes(1)));
                }
            }
            assertEquals(size + 1, runtime.snapshot().activeInvocations());
            var completion = pool.submit(root::revoke);
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            try {
                assertEquals(AgentEndReason.REVOKED, root.endReason());
                assertTrue(
                        descendants.stream()
                                .allMatch(
                                        node -> node.endReason() == AgentEndReason.PARENT_REVOKED));
                assertNull(other.endReason());
                assertFalse(completion.isDone());
            } finally {
                release.countDown();
            }
            completion.get(10, TimeUnit.SECONDS);
            assertEquals(1, runtime.snapshot().activeInvocations());
            assertEquals(1023L, runtime.snapshot().ended().get(AgentEndReason.PARENT_REVOKED));
            var ends =
                    telemetry.drain(4096).stream()
                            .filter(record -> record.endReason() != null)
                            .toList();
            assertEquals(size, ends.size());
            assertEquals(size, ends.stream().map(TelemetryRecord::invocationId).distinct().count());
            assertEquals(0, telemetry.snapshot().dropped());
            other.call(() -> null);
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }
}
