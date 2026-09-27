package io.agentsecurity.core;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecurityContextsTest {

    static final SecurityContext A =
            SecurityContext.authenticated("tenant-a", "principal-a", Set.of("customers:read"));

    static final SecurityContext B =
            SecurityContext.authenticated("tenant-b", "principal-b", Set.of());

    @TempDir Path directory;

    @Test
    void scopesRestoreAfterErrorsAndRejectOutOfOrderClose() {
        assertNull(SecurityContexts.current());
        try (var outer = SecurityContexts.open(A)) {
            try (var inner = SecurityContexts.open(B)) {
                assertSame(B, SecurityContexts.current());
                assertThrows(IllegalStateException.class, outer::close);
            }
            assertSame(A, SecurityContexts.current());
            assertThrows(
                    IllegalStateException.class,
                    () -> {
                        try (var ignored = SecurityContexts.restore(null)) {
                            assertNull(SecurityContexts.current());
                            throw new IllegalStateException();
                        }
                    });
            assertSame(A, SecurityContexts.current());
        }
        assertNull(SecurityContexts.current());
    }

    @Test
    void crossThreadCloseIsRejectedAndPlainThreadsDoNotInheritIdentity() throws Exception {
        var executor = Executors.newSingleThreadExecutor();
        try (var scope = SecurityContexts.open(A)) {
            executor.submit(
                            () -> {
                                assertNull(SecurityContexts.current());
                                assertThrows(IllegalStateException.class, scope::close);
                            })
                    .get(2, TimeUnit.SECONDS);
            assertSame(A, SecurityContexts.current());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void capturedNullClearsWorkerIdentityAndRestoresItAfterTask() {
        Runnable empty =
                SecurityContexts.wrap((Runnable) () -> assertNull(SecurityContexts.current()));
        try (var ignored = SecurityContexts.open(B)) {
            empty.run();
            assertSame(B, SecurityContexts.current());
        }
        Runnable captured;
        try (var ignored = SecurityContexts.open(A)) {
            captured =
                    SecurityContexts.wrap(
                            (Runnable) () -> assertSame(A, SecurityContexts.current()));
        }
        try (var ignored = SecurityContexts.open(B)) {
            captured.run();
            assertSame(B, SecurityContexts.current());
        }
    }

    @Test
    void reusedExecutorPropagatesEachSubmissionAndDoesNotLeakAcrossTasks() throws Exception {
        ExecutorService raw = Executors.newFixedThreadPool(2);
        ExecutorService wrapped = SecurityContexts.executorService(raw);
        try {
            List<Future<?>> work = new ArrayList<>();
            for (int i = 0; i < 100; i++) {
                SecurityContext expected = i % 2 == 0 ? A : B;
                try (var ignored = SecurityContexts.open(expected)) {
                    work.add(
                            wrapped.submit(() -> assertSame(expected, SecurityContexts.current())));
                }
            }
            for (var task : work) {
                task.get(2, TimeUnit.SECONDS);
            }
            assertNull(raw.submit(SecurityContexts::current).get(2, TimeUnit.SECONDS));
            assertNull(wrapped.submit(SecurityContexts::current).get(2, TimeUnit.SECONDS));
            assertSame(wrapped, SecurityContexts.executor(wrapped));
        } finally {
            wrapped.shutdownNow();
        }
        assertTrue(raw.isShutdown());
    }

    @Test
    void eventSnapshotSurvivesScopeAndDetectorThreadHop() {
        SecurityEvent event;
        try (var ignored = SecurityContexts.open(A)) {
            event = new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "lookup", "{}");
        }
        assertSame(A, event.context());
        assertNull(SecurityContexts.current());
        try (var engine =
                new PolicyEngine(
                        List.of(
                                new RequiredContextPolicy(),
                                input -> {
                                    assertSame(A, input.context());
                                    assertSame(A, SecurityContexts.current());
                                    return Decision.allow();
                                }),
                        (input, decision) -> {})) {
            engine.check(event);
        }
        assertNull(SecurityContexts.current());
        assertFalse(event.toString().contains("tenant-a"));
        assertFalse(A.toString().contains("principal-a"));
    }

    @Test
    void modelSuppliedIdentityCannotSatisfyRequiredContext() {
        var event =
                new SecurityEvent(
                        SecurityEvent.Phase.MODEL_INPUT,
                        "chat",
                        "{\"tenantId\":\"tenant-a\",\"permissions\":[\"customers:read\"]}");
        assertEquals(
                "missing-security-context", new RequiredContextPolicy().evaluate(event).ruleId());
        Set<String> source = new HashSet<>(Set.of("read"));
        SecurityContext context = SecurityContext.authenticated("tenant", "user", source);
        source.clear();
        assertEquals(Set.of("read"), context.permissions());
        assertThrows(UnsupportedOperationException.class, () -> context.permissions().clear());
    }

    @Test
    void auditCorrelatesRunWithoutRecordingIdentityOrPermissions() throws Exception {
        Path file = directory.resolve("audit.jsonl");
        try (var sink = new FileAuditSink(file, 2048, 1, false, "v1");
                var ignored = SecurityContexts.open(A)) {
            sink.accept(
                    new SecurityEvent(SecurityEvent.Phase.MODEL_INPUT, "chat", "private"),
                    Decision.allow());
            sink.accept(
                    new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "lookup", "private"),
                    Decision.allow());
        }
        var lines = Files.readAllLines(file);
        assertEquals(2, lines.size());
        assertTrue(
                lines.stream().allMatch(line -> line.contains("\"runId\":\"" + A.runId() + "\"")));
        assertFalse(Files.readString(file).contains("tenant-a"));
        assertFalse(Files.readString(file).contains("customers:read"));
    }
}
