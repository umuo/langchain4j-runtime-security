package io.agentsecurity.core.versioning;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 验证发布竞争、回滚 ABA 防护、在途一致性和最终文件审计版本。 */
class AtomicPolicyTest {
    @TempDir Path directory;
    private final SecurityEvent event =
            new SecurityEvent(SecurityEvent.Phase.MODEL_INPUT, "chat", "private");

    private PolicyRevision revision(String version, boolean allowed) {
        return new PolicyRevision(
                version,
                (allowed ? "a" : "b").repeat(64),
                e -> allowed ? Decision.allow() : Decision.deny("version-denied"));
    }

    @Test
    void stalePublishVersionReuseAndFullHistoryLeaveCurrentUnchanged() {
        var policies = new AtomicPolicy(revision("v1", true), 2);
        policies.publish(1, revision("v2", false));
        assertThrows(IllegalStateException.class, () -> policies.publish(1, revision("v3", true)));
        assertThrows(
                IllegalArgumentException.class, () -> policies.publish(2, revision("v1", false)));
        assertThrows(IllegalStateException.class, () -> policies.publish(2, revision("v3", true)));
        assertThrows(IllegalArgumentException.class, () -> policies.rollback(2, "unknown"));
        assertEquals("v2", policies.state().version());
        policies.rollback(2, "v1");
        assertEquals(3, policies.state().generation());
        assertThrows(IllegalStateException.class, () -> policies.publish(1, revision("v2", false)));
        assertThrows(UnsupportedOperationException.class, () -> policies.versions().clear());
    }

    @Test
    void competingPublishersHaveExactlyOneWinner() throws Exception {
        var policies = new AtomicPolicy(revision("v1", true), 4);
        var start = new CountDownLatch(1);
        var pool = Executors.newFixedThreadPool(2);
        try {
            var tasks = new java.util.ArrayList<Future<Boolean>>();
            for (String version : List.of("v2", "v3")) {
                tasks.add(
                        pool.submit(
                                () -> {
                                    start.await();
                                    try {
                                        policies.publish(1, revision(version, false));
                                        return true;
                                    } catch (IllegalStateException conflict) {
                                        return false;
                                    }
                                }));
            }
            start.countDown();
            assertNotEquals(
                    tasks.get(0).get(2, TimeUnit.SECONDS), tasks.get(1).get(2, TimeUnit.SECONDS));
            assertEquals(2, policies.state().generation());
            assertEquals(2, policies.versions().size());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void inFlightAndPinnedChecksKeepTheSelectedVersionInFileAudit() throws Exception {
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var v1 =
                new PolicyRevision(
                        "v1",
                        "a".repeat(64),
                        e -> {
                            entered.countDown();
                            try {
                                if (!release.await(3, TimeUnit.SECONDS)) {
                                    return Decision.deny("test-timeout");
                                }
                            } catch (InterruptedException stopped) {
                                Thread.currentThread().interrupt();
                                return Decision.deny("test-interrupted");
                            }
                            return Decision.allow();
                        });
        var policies = new AtomicPolicy(v1, 4);
        Path journal = directory.resolve("audit.jsonl");
        var caller = Executors.newSingleThreadExecutor();
        try (var audit = new FileAuditSink(journal, 100000, 2, false, "static-v0");
                var engine =
                        new PolicyEngine(
                                List.of(policies),
                                audit,
                                new DetectionLimits(Duration.ofSeconds(5), 2));
                var pinned = engine.pinPolicy()) {
            var pending = caller.submit(() -> engine.check(event));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            policies.publish(1, revision("v2", false));
            release.countDown();
            pending.get(2, TimeUnit.SECONDS);
            assertThrows(SecurityBlockedException.class, () -> engine.check(event));
            pinned.check(event);
            policies.rollback(2, "v1");
            engine.check(event);
        } finally {
            release.countDown();
            caller.shutdownNow();
        }
        var lines = Files.readAllLines(journal);
        assertEquals(4, lines.size());
        assertTrue(lines.get(0).contains("\"policyVersion\":\"v1\""));
        assertTrue(lines.get(1).contains("\"policyVersion\":\"v2\""));
        assertTrue(lines.get(1).contains("\"decision\":\"DENY\""));
        assertTrue(lines.get(2).contains("\"policyVersion\":\"v1\""));
        assertTrue(lines.get(3).contains("\"policyVersion\":\"v1\""));
        assertFalse(Files.readString(journal).contains("private"));
    }

    @Test
    void snapshotFailureIsAuditedAsUnresolvedAndCannotAllow() {
        VersionedDetector broken =
                () -> {
                    throw new IllegalStateException("private");
                };
        var observed = new AtomicReference<Decision>();
        try (var engine = new PolicyEngine(List.of(broken), (e, d) -> observed.set(d))) {
            assertThrows(SecurityBlockedException.class, () -> engine.check(event));
            assertEquals("unresolved", observed.get().policyVersion());
            assertFalse(observed.get().allowed());
        }
    }

    @Test
    void laterDetectorDenialRetainsSelectedVersionAndClosingOwnerInvalidatesPinnedView() {
        var policies = new AtomicPolicy(revision("v1", true), 2);
        var observed = new AtomicReference<Decision>();
        try (var engine =
                        new PolicyEngine(
                                List.of(policies, e -> Decision.deny("fixed-denial")),
                                (e, d) -> observed.set(d));
                var pinned = engine.pinPolicy()) {
            assertThrows(SecurityBlockedException.class, () -> pinned.check(event));
            assertEquals("v1", observed.get().policyVersion());
            assertEquals("fixed-denial", observed.get().ruleId());
            engine.close();
            assertEquals(
                    "detector-closed",
                    assertThrows(SecurityBlockedException.class, () -> pinned.check(event))
                            .ruleId());
        }
    }
}
