package io.agentsecurity.fixture;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class RagIT {

    @TempDir Path temporary;

    @ParameterizedTest
    @CsvSource({
        "rag-allowed,false,1,1,allow",
        "rag-input,true,0,0,denied-text",
        "rag-output,true,1,0,denied-text",
        "rag-metadata,true,1,0,denied-text",
        "rag-source,true,0,0,retriever-not-allowed",
        "rag-permission,true,0,0,rag-permission-denied",
        "rag-lambda-output,true,1,0,denied-text",
        "rag-transformed-input,true,0,0,denied-text",
        "rag-async,false,1,1,allow",
        "rag-async-output,true,1,0,denied-text",
        "rag-offload,false,1,1,allow",
        "rag-parallel,false,2,1,allow",
        "rag-custom-executor,false,2,1,allow",
        "rag-custom-augmentor-output,true,0,0,denied-text",
        "rag-direct,false,1,0,allow",
        "rag-direct-async,false,1,0,allow",
        "rag-size,true,1,0,rag-content-limit",
        "rag-missing,true,0,0,missing-security-context",
        "rag-null-future,true,1,0,null-result"
    })
    void checksRagBeforeReadsAndBeforeReleasingResults(
            String scenario, boolean blocked, int reads, int models, String reason)
            throws Exception {
        Path root = Path.of("..").toAbsolutePath().normalize();
        Path policy = temporary.resolve("policy.properties"),
                audit = temporary.resolve("audit.jsonl"),
                log = temporary.resolve("process.log");
        Properties properties = new Properties();
        properties.setProperty("context.required", "true");
        properties.setProperty("deny.text", "RAG_SECRET");
        properties.setProperty("policy.version", "rag-v1");
        properties.setProperty("audit.path", audit.toString());
        if (scenario.equals("rag-source")) {
            properties.setProperty("allow.retrievers", "");
        }
        try (var writer = Files.newBufferedWriter(policy)) {
            properties.store(writer, "RAG fixture");
        }
        Process process =
                new ProcessBuilder(
                                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                                "-javaagent:"
                                        + root.resolve(
                                                "agent-security-javaagent/target/agent-security-javaagent.jar")
                                        + "="
                                        + policy,
                                "-jar",
                                root.resolve("integration-spring-boot/target/boot-fixture.jar")
                                        .toString(),
                                "--scenario=" + scenario,
                                "--spring.main.banner-mode=off",
                                "--logging.level.root=ERROR")
                        .redirectErrorStream(true)
                        .redirectOutput(log.toFile())
                        .start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            fail("RAG fixture timed out: " + Files.readString(log));
        }
        String output = Files.readString(log), journal = Files.readString(audit);
        assertEquals(0, process.exitValue(), output);
        assertTrue(
                output.contains(
                        "RAG_RESULT scenario="
                                + scenario
                                + " blocked="
                                + blocked
                                + " reads="
                                + reads
                                + " modelCalls="
                                + models
                                + " restored=true"),
                output);
        if (blocked) {
            assertTrue(output.contains("BLOCK_REASON=" + reason), output);
        }
        assertFalse(output.contains("TRANSFORM_ERROR"), output);
        assertFalse(journal.contains("RAG_SECRET"));
        assertFalse(output.contains("RAG_SECRET"));
        assertFalse(journal.contains("rag-tenant"));
        assertFalse(journal.contains("rag-user"));
        Set<String> runs = new HashSet<>();
        var matcher = Pattern.compile("\"runId\":\"([a-f0-9-]+)\"").matcher(journal);
        while (matcher.find()) {
            runs.add(matcher.group(1));
        }
        assertEquals(scenario.equals("rag-missing") ? 0 : 1, runs.size(), journal);
        if (!scenario.equals("rag-missing")) {
            assertFalse(journal.contains("\"runId\":null"), journal);
        }
        if (reads > 0) {
            assertTrue(journal.contains("RETRIEVAL_INPUT"), journal);
        }
        if (!blocked && reads > 0) {
            assertTrue(journal.contains("RETRIEVAL_OUTPUT"), journal);
        }
        if (!scenario.startsWith("rag-direct")) {
            assertTrue(journal.contains("AUGMENTATION_INPUT"), journal);
        }
        if (!blocked && models > 0) {
            assertTrue(journal.contains("AUGMENTATION_OUTPUT"), journal);
        }
    }
}
