package io.agentsecurity.fixture;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class BootIT {

    @TempDir Path temporary;

    @ParameterizedTest
    @CsvSource({
        "tool,true,1,0",
        "allowed,false,2,1",
        "plugin,true,0,0",
        "plugin-timeout,true,0,0",
        "plugin-error,true,0,0",
        "http-input,true,0,0",
        "http-output,true,1,0",
        "http-allowed,false,1,0",
        "http-async-input,true,0,0",
        "http-async-output,true,1,0",
        "http-async-allowed,false,1,0",
        "http-stream-input,true,0,0",
        "http-stream-output,true,1,0",
        "http-stream-allowed,false,1,0",
        "http-reactive-input,true,0,0",
        "http-reactive-output,true,1,0",
        "http-reactive-allowed,false,1,0",
        "http-reactive-text-input,true,0,0",
        "http-reactive-text-output,true,1,0",
        "http-reactive-text-allowed,false,1,0",
        "http-reactive-cancel,false,0,0",
        "args-allowed,false,2,1",
        "args-denied,true,1,0",
        "args-escaped,true,1,0",
        "args-duplicate,true,1,0"
    })
    void actualBootJarAndOfficialProvider(String scenario, boolean blocked, int models, int tools)
            throws Exception {
        Path root = Path.of("..").toAbsolutePath().normalize();
        Path log = temporary.resolve("boot.log");
        Path audit = temporary.resolve("decisions.jsonl");
        Path policy = temporary.resolve("policy.properties");
        var properties = new java.util.Properties();
        try (var reader = Files.newBufferedReader(root.resolve("config/demo.properties"))) {
            properties.load(reader);
        }
        properties.setProperty("audit.path", audit.toString());
        properties.setProperty("policy.version", "boot-test-v1");
        if (scenario.startsWith("args-")) {
            properties.setProperty(
                    "tool.policy.path", root.resolve("config/tool-policy-example.json").toString());
        }
        try (var writer = Files.newBufferedWriter(policy)) {
            properties.store(writer, "Boot integration policy");
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
            fail("Boot child timed out: " + Files.readString(log));
        }
        String output = Files.readString(log);
        assertEquals(0, process.exitValue(), output);
        assertTrue(
                output.contains(
                        "BOOT_RESULT scenario="
                                + scenario
                                + " blocked="
                                + blocked
                                + " modelCalls="
                                + models
                                + " toolCalls="
                                + tools),
                output);
        assertFalse(output.contains("DEMO_SECRET_123"), output);
        String journal = Files.readString(audit);
        assertFalse(journal.isBlank());
        assertTrue(journal.contains("\"policyVersion\":\"boot-test-v1\""), journal);
        assertFalse(journal.contains("DEMO_SECRET_123"));
        assertFalse(journal.contains("PLUGIN_"));
        assertFalse(journal.contains("sensitive detector detail"));
        assertEquals(blocked, journal.contains("\"decision\":\"DENY\""), journal);
        if (blocked && (scenario.contains("stream") || scenario.contains("reactive"))) {
            assertTrue(output.contains("chunks=0"), output);
        }
        if (scenario.equals("http-stream-allowed")
                || scenario.equals("http-reactive-allowed")
                || scenario.equals("http-reactive-text-allowed")) {
            assertTrue(output.contains("chunks=2"), output);
        }
        if (scenario.equals("http-reactive-cancel")) {
            assertTrue(output.contains("chunks=0"), output);
        }
        if (scenario.equals("plugin")) {
            assertTrue(output.contains("boot-plugin"), output);
        }
        if (scenario.equals("plugin-timeout")) {
            assertTrue(output.contains("detector-timeout"), output);
        }
        if (scenario.equals("plugin-error")) {
            assertTrue(output.contains("detector-error"), output);
            assertFalse(output.contains("sensitive detector detail"), output);
        }
        if (scenario.endsWith("output")) {
            assertTrue(output.contains("Agent security blocked operation: denied-text"), output);
        }
        if (scenario.equals("args-denied") || scenario.equals("args-escaped")) {
            assertTrue(output.contains("tool-argument-policy"), output);
        }
        if (scenario.equals("args-duplicate")) {
            assertTrue(output.contains("invalid-tool-arguments"), output);
        }
        assertFalse(journal.contains("other-customer"), journal);
    }
}
