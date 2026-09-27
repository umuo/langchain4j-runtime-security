package io.agentsecurity.fixture;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import static org.junit.jupiter.api.Assertions.*;

class ContextIT {
    @TempDir Path temporary;
    @ParameterizedTest
    @CsvSource({"context-sync,false,2,1,allow", "context-async,false,2,1,allow", "context-overlap,false,4,2,allow",
            "context-parallel,false,2,1,allow", "context-custom-executor,false,2,1,allow",
            "context-missing,true,0,0,missing-security-context", "context-permission,true,1,0,permission-denied",
            "context-spoof,true,1,0,tool-argument-policy", "context-stream,false,1,0,allow",
            "context-reactive,false,1,0,allow", "context-reactive-mismatch,true,0,0,security-context-mismatch"})
    void contextSurvivesRealFrameworkBoundariesWithoutTenantLeakage(String scenario, boolean blocked, int models, int tools, String reason) throws Exception {
        Path root = Path.of("..").toAbsolutePath().normalize();
        Path policy = temporary.resolve("policy.properties"), audit = temporary.resolve("audit.jsonl"), log = temporary.resolve("process.log");
        Properties properties = new Properties();
        properties.setProperty("context.required", "true");
        properties.setProperty("tool.policy.path", root.resolve("config/context-tool-policy-example.json").toString());
        properties.setProperty("audit.path", audit.toString()); properties.setProperty("policy.version", "context-v1");
        try (var writer = Files.newBufferedWriter(policy)) { properties.store(writer, "Context fixture"); }
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-javaagent:" + root.resolve("agent-security-javaagent/target/agent-security-javaagent.jar") + "=" + policy,
                "-jar", root.resolve("integration-spring-boot/target/boot-fixture.jar").toString(), "--scenario=" + scenario,
                "--spring.main.banner-mode=off", "--logging.level.root=ERROR")
                .redirectErrorStream(true).redirectOutput(log.toFile()).start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) { process.destroyForcibly(); fail("Context fixture timed out: " + Files.readString(log)); }
        String output = Files.readString(log), journal = Files.readString(audit);
        assertEquals(0, process.exitValue(), output);
        assertTrue(output.contains("CONTEXT_RESULT scenario=" + scenario + " blocked=" + blocked + " modelCalls=" + models + " toolCalls=" + tools + " restored=true"), output);
        if (blocked) assertTrue(output.contains("BLOCK_REASON=" + reason), output);
        assertFalse(journal.contains("tenant-a")); assertFalse(journal.contains("tenant-b")); assertFalse(journal.contains("principal-"));
        Set<String> runs = new HashSet<>();
        var matcher = Pattern.compile("\"runId\":\"([a-f0-9-]+)\"").matcher(journal);
        while (matcher.find()) runs.add(matcher.group(1));
        assertEquals(scenario.equals("context-missing") ? 0 : scenario.equals("context-overlap") ? 2 : 1, runs.size(), journal);
        if (!scenario.equals("context-missing")) assertFalse(journal.contains("\"runId\":null"), journal);
        if (tools > 0) assertTrue(journal.contains("TOOL_INPUT") && journal.contains("TOOL_OUTPUT"), journal);
    }
}
