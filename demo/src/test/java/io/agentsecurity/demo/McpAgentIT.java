package io.agentsecurity.demo;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class McpAgentIT {
    @TempDir Path directory;

    @ParameterizedTest
    @CsvSource({
        "allowed,allow,1",
        "async,allow,1",
        "server,mcp-tool-not-allowed,0",
        "tool,mcp-tool-not-allowed,0",
        "default,mcp-tool-not-allowed,0",
        "async-deny,mcp-tool-not-allowed,0",
        "input,denied-text,0",
        "output,denied-text,1",
        "async-output,denied-text,1",
        "invalid,invalid-mcp-name,0",
        "metadata,mcp-result-attributes-unsupported,1",
        "delegation,agent-tool-denied,0",
        "async-ended,agent-runtime-closed,1",
        "version,unsupported-mcp-version,0"
    })
    void realClientBoundary(String scenario, String rule, int calls) throws Exception {
        Path root = Path.of("..").toAbsolutePath().normalize();
        var properties = new Properties();
        properties.setProperty("deny.text", "secret-marker");
        if (!scenario.equals("default") && !scenario.equals("async-deny")) {
            properties.setProperty("allow.mcp.tools", "mcp:inventory/lookup");
        }
        properties.setProperty("detector.timeout.millis", "3000");
        Path config = directory.resolve("policy.properties");
        try (var output = Files.newBufferedWriter(config)) {
            properties.store(output, "MCP acceptance");
        }
        // 在子进程类路径前端提供错误的 MCP 版本元数据，验证实际入口会拒绝。
        if (scenario.equals("version")) {
            Path metadata =
                    directory.resolve(
                            "META-INF/maven/dev.langchain4j/langchain4j-mcp/pom.properties");
            Files.createDirectories(metadata.getParent());
            Files.writeString(metadata, "version=0.0.0\n");
        }
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
                                directory
                                        + java.io.File.pathSeparator
                                        + root.resolve("demo/target/test-classes")
                                        + java.io.File.pathSeparator
                                        + root.resolve("demo/target/agent-security-demo.jar"),
                                "io.agentsecurity.demo.McpApplication",
                                scenario)
                        .redirectErrorStream(true)
                        .redirectOutput(log.toFile())
                        .start();
        if (!process.waitFor(25, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            fail("MCP child timed out");
        }
        String output = Files.readString(log);
        assertEquals(0, process.exitValue(), output);
        assertTrue(output.contains("MCP_RESULT rule=" + rule + " calls=" + calls), output);
    }
}
