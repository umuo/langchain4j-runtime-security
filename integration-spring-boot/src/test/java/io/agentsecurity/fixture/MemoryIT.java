package io.agentsecurity.fixture;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import static org.junit.jupiter.api.Assertions.*;

class MemoryIT {
    @TempDir Path temporary;
    @ParameterizedTest
    @CsvSource({"memory-read,false,1,0,0,0,1,allow", "memory-write,false,1,1,0,0,2,allow",
            "memory-read-output,true,1,0,0,0,2,denied-text", "memory-write-input,true,0,0,0,0,1,denied-text",
            "memory-batch,true,0,0,0,0,1,denied-text", "memory-set,true,0,0,0,0,1,denied-text",
            "memory-clear,false,0,0,1,0,0,allow", "memory-deny-read,true,0,0,0,0,1,permission-denied",
            "memory-deny-write,true,0,0,0,0,1,permission-denied", "memory-deny-delete,true,0,0,0,0,1,permission-denied",
            "memory-owner,true,0,0,0,0,1,memory-owner-denied", "memory-missing,true,0,0,0,0,1,missing-security-context",
            "memory-store-read-output,true,1,0,0,0,2,denied-text", "memory-store-write-input,true,0,0,0,0,1,denied-text",
            "memory-store-async-read-output,true,1,0,0,0,2,denied-text", "memory-async-write-input,true,0,0,0,0,1,denied-text",
            "memory-async-read,false,1,0,0,0,1,allow", "memory-async-delete,false,0,0,1,0,0,allow",
            "memory-ai,false,-1,2,0,1,3,allow", "memory-ai-async,false,-1,2,0,1,3,allow",
            "memory-ai-read-output,true,1,0,0,0,2,denied-text", "memory-size,true,1,0,0,0,257,memory-message-limit",
            "memory-unsupported-id,true,0,0,0,0,1,unsupported-memory-id"})
    void protectsActualMemoryAndStoreBoundaries(String scenario, boolean blocked, int reads, int writes, int deletes, int models, int remaining, String reason) throws Exception {
        Path root = Path.of("..").toAbsolutePath().normalize();
        Path policy = temporary.resolve("policy.properties"), audit = temporary.resolve("audit.jsonl"), log = temporary.resolve("process.log");
        Properties p = new Properties(); p.setProperty("context.required", "true"); p.setProperty("deny.text", "MEMORY_SECRET");
        p.setProperty("memory.read.permission", "memory:read"); p.setProperty("memory.write.permission", "memory:write"); p.setProperty("memory.delete.permission", "memory:delete");
        p.setProperty("audit.path", audit.toString()); p.setProperty("policy.version", "memory-v1");
        try (var writer = Files.newBufferedWriter(policy)) { p.store(writer, "Memory fixture"); }
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-javaagent:" + root.resolve("agent-security-javaagent/target/agent-security-javaagent.jar") + "=" + policy,
                "-jar", root.resolve("integration-spring-boot/target/boot-fixture.jar").toString(), "--scenario=" + scenario,
                "--spring.main.banner-mode=off", "--logging.level.root=ERROR")
                .redirectErrorStream(true).redirectOutput(log.toFile()).start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) { process.destroyForcibly(); fail("Memory timed out: " + Files.readString(log)); }
        String output = Files.readString(log), journal = Files.readString(audit);
        assertEquals(0, process.exitValue(), output);
        String count = reads < 0 ? "[1-9][0-9]*" : Integer.toString(reads);
        assertTrue(Pattern.compile("MEMORY_RESULT scenario=" + scenario + " blocked=" + blocked + " reads=" + count
                + " writes=" + writes + " deletes=" + deletes + " modelCalls=" + models + " remaining=" + remaining + " restored=true").matcher(output).find(), output);
        if (blocked) assertTrue(output.contains("BLOCK_REASON=" + reason), output);
        assertFalse(output.contains("TRANSFORM_ERROR"), output);
        for (String secret : List.of("MEMORY_SECRET", "private-memory-session", "memory-tenant", "memory-user")) assertFalse(journal.contains(secret), journal);
        if (!scenario.equals("memory-unsupported-id")) {
            assertTrue(journal.contains("MEMORY_"), journal);
            if (!scenario.equals("memory-missing")) {
                assertFalse(journal.contains("\"runId\":null"), journal);
                Set<String> runs = new HashSet<>(); var matcher = Pattern.compile("\"runId\":\"([a-f0-9-]+)\"").matcher(journal);
                while (matcher.find()) runs.add(matcher.group(1)); assertEquals(1, runs.size(), journal);
            }
        }
    }
}
