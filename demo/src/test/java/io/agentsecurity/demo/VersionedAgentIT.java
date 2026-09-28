package io.agentsecurity.demo;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.jar.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class VersionedAgentIT {
    @TempDir Path directory;

    @Test
    void packagedAgentUsesVersionedSpiAndUpdatesFileAudit() throws Exception {
        Path root = Path.of("..").toAbsolutePath().normalize();
        Path service = directory.resolve("service.jar");
        try (var jar = new JarOutputStream(Files.newOutputStream(service))) {
            jar.putNextEntry(new JarEntry("META-INF/services/io.agentsecurity.core.Detector"));
            jar.write(
                    "io.agentsecurity.demo.VersionedApplication\n"
                            .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            jar.closeEntry();
        }
        Path audit = directory.resolve("audit.jsonl");
        var properties = new Properties();
        properties.setProperty("audit.path", audit.toString());
        properties.setProperty("policy.version", "static-v0");
        Path config = directory.resolve("policy.properties");
        try (var output = Files.newBufferedWriter(config)) {
            properties.store(output, "Versioned SPI test");
        }
        String classpath =
                String.join(
                        java.io.File.pathSeparator,
                        service.toString(),
                        root.resolve("demo/target/test-classes").toString(),
                        root.resolve("demo/target/agent-security-demo.jar").toString());
        Path log = directory.resolve("process.log");
        var process =
                new ProcessBuilder(
                                Path.of(System.getProperty("java.home"), "bin/java").toString(),
                                "-javaagent:"
                                        + root.resolve(
                                                "agent-security-javaagent/target/agent-security-javaagent.jar")
                                        + "="
                                        + config,
                                "-cp",
                                classpath,
                                "io.agentsecurity.demo.VersionedApplication")
                        .redirectErrorStream(true)
                        .redirectOutput(log.toFile())
                        .start();
        if (!process.waitFor(25, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            fail("Versioned child timed out");
        }
        String output = Files.readString(log);
        assertEquals(0, process.exitValue(), output);
        assertTrue(output.contains("POLICY_CYCLE_OK calls=2 generation=3"), output);
        String journal = Files.readString(audit);
        assertTrue(journal.contains("\"policyVersion\":\"v1\""), journal);
        assertTrue(
                journal.lines()
                        .anyMatch(
                                line ->
                                        line.contains("\"policyVersion\":\"v2\"")
                                                && line.contains("\"decision\":\"DENY\"")),
                journal);
        assertFalse(journal.contains("static-v0"), journal);
        assertFalse(journal.contains("hot-block"), journal);
    }
}
