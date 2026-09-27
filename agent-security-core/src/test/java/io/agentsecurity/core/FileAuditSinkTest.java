package io.agentsecurity.core;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.List;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileAuditSinkTest {

    @TempDir Path directory;

    @Test
    void onlyBoundedMetadataIsRecordedAndPrivateFilesAreCreated() throws Exception {
        Path log = directory.resolve("decisions.jsonl");
        var event =
                new SecurityEvent(
                        SecurityEvent.Phase.TOOL_INPUT,
                        "secret-tool\n\"injected\"",
                        "secret-payload");
        try (var sink = new FileAuditSink(log, 1024, 2, true, "policy-1")) {
            sink.accept(event, Decision.deny("blocked"));
        }
        String text = Files.readString(log);
        assertTrue(text.contains(event.id().toString()));
        assertTrue(text.contains("\"decision\":\"DENY\""));
        assertTrue(text.contains("\"policyVersion\":\"policy-1\""));
        assertEquals(1, text.lines().count());
        assertFalse(text.contains("secret"));
        assertFalse(event.toString().contains("secret"));
        if (Files.getFileStore(log).supportsFileAttributeView("posix")) {
            assertEquals(
                    "rw-------",
                    java.nio.file.attribute.PosixFilePermissions.toString(
                            Files.getPosixFilePermissions(log)));
        }
    }

    @Test
    void journalIsExclusiveAndRotatesWithBoundedRetention() throws Exception {
        Path log = directory.resolve("decisions.jsonl");
        try (var sink = new FileAuditSink(log, 1024, 2, false, "v1")) {
            assertThrows(Exception.class, () -> new FileAuditSink(log, 1024, 2, false, "v1"));
            for (int i = 0; i < 40; i++) {
                sink.accept(
                        new SecurityEvent(SecurityEvent.Phase.MODEL_INPUT, "chat", "private"),
                        Decision.allow());
            }
        }
        for (Path file :
                List.of(
                        log,
                        directory.resolve("decisions.jsonl.1"),
                        directory.resolve("decisions.jsonl.2"))) {
            assertTrue(Files.size(file) <= 1024);
            assertTrue(Files.readString(file).endsWith("\n"));
        }
        assertFalse(Files.exists(directory.resolve("decisions.jsonl.3")));
        try (var reopened = new FileAuditSink(log, 1024, 2, false, "v2")) {
            reopened.accept(
                    new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "t", "x"), Decision.allow());
        }
    }

    @Test
    void concurrentWritesDoNotInterleaveAndClosedSinkFailsClosed() throws Exception {
        Path log = directory.resolve("decisions.jsonl");
        var sink = new FileAuditSink(log, 1_000_000, 2, false, "v1");
        ExecutorService workers = Executors.newFixedThreadPool(6);
        try {
            var tasks = new java.util.ArrayList<Future<?>>();
            for (int i = 0; i < 100; i++) {
                tasks.add(
                        workers.submit(
                                () ->
                                        sink.accept(
                                                new SecurityEvent(
                                                        SecurityEvent.Phase.MODEL_INPUT,
                                                        "chat",
                                                        "private"),
                                                Decision.allow())));
            }
            for (var task : tasks) {
                task.get(5, TimeUnit.SECONDS);
            }
        } finally {
            workers.shutdownNow();
            sink.close();
        }
        List<String> lines = Files.readAllLines(log);
        assertEquals(100, lines.size());
        assertTrue(
                lines.stream()
                        .allMatch(
                                s ->
                                        s.startsWith("{")
                                                && s.endsWith("}")
                                                && s.contains("\"schemaVersion\":3")));
        try (var engine = new PolicyEngine(List.of(), sink)) {
            assertEquals(
                    "audit-error",
                    assertThrows(
                                    SecurityBlockedException.class,
                                    () ->
                                            engine.check(
                                                    new SecurityEvent(
                                                            SecurityEvent.Phase.TOOL_INPUT,
                                                            "t",
                                                            "x")))
                            .ruleId());
        }
    }

    @Test
    void symlinkAndInvalidIdentifiersAreRejected() throws Exception {
        Path target = directory.resolve("target");
        Files.writeString(target, "unchanged");
        Path link = directory.resolve("link");
        Files.createSymbolicLink(link, target);
        assertThrows(java.io.IOException.class, () -> new FileAuditSink(link, 1024, 2, true, "v1"));
        assertEquals("unchanged", Files.readString(target));
        assertThrows(IllegalArgumentException.class, () -> Decision.deny("payload\n\"injected"));
    }

    @Test
    void rotationFailureRemainsRejectedAfterObstacleIsRemoved() throws Exception {
        Path log = directory.resolve("decisions.jsonl");
        Path obstacle = directory.resolve("decisions.jsonl.1");
        try (var sink = new FileAuditSink(log, 1024, 2, false, "v1");
                var engine = new PolicyEngine(List.of(), sink)) {
            Files.createDirectory(obstacle);
            var event = new SecurityEvent(SecurityEvent.Phase.MODEL_INPUT, "chat", "private");
            SecurityBlockedException failure = null;
            for (int i = 0; i < 10; i++) {
                try {
                    engine.check(event);
                } catch (SecurityBlockedException blocked) {
                    failure = blocked;
                    break;
                }
            }
            assertNotNull(failure);
            assertEquals("audit-error", failure.ruleId());
            Files.delete(obstacle);
            long size = Files.size(log);
            assertThrows(SecurityBlockedException.class, () -> engine.check(event));
            assertEquals(size, Files.size(log));
        }
    }
}
