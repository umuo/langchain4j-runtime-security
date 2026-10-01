package io.agentsecurity.demo;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.mcp.McpOperations;
import java.nio.file.*;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class McpTransportIT {
    @TempDir Path directory;

    static Stream<Arguments> scenarios() {
        return Stream.of("http", "sse", "stdio")
                .flatMap(
                        mode ->
                                List.of(
                                                "resource,allow,allow,1",
                                                "resource,default,mcp-resource-not-allowed,0",
                                                "resource,server,mcp-resource-not-allowed,0",
                                                "resource,target,mcp-resource-not-allowed,0",
                                                "resource,output,denied-text,1",
                                                "resource,uri,mcp-resource-uri-mismatch,1",
                                                "resource,binary,unsupported-mcp-content,1",
                                                "resource,limit,mcp-content-limit,1",
                                                "resource,delegation,agent-tool-denied,0",
                                                "prompt,allow,allow,1",
                                                "prompt,default,mcp-prompt-not-allowed,0",
                                                "prompt,server,mcp-prompt-not-allowed,0",
                                                "prompt,target,mcp-prompt-not-allowed,0",
                                                "prompt,input,denied-text,0",
                                                "prompt,output,denied-text,1",
                                                "prompt,description,denied-text,1",
                                                "prompt,binary,unsupported-mcp-content,1",
                                                "prompt,limit,mcp-content-limit,1",
                                                "prompt,delegation,agent-tool-denied,0",
                                                "tool,allow,allow,1",
                                                "tool,default,mcp-tool-not-allowed,0",
                                                "tool,output,denied-text,1")
                                        .stream()
                                        .map(
                                                value -> {
                                                    var fields = value.split(",");
                                                    return Arguments.of(
                                                            mode,
                                                            fields[0],
                                                            fields[1],
                                                            fields[2],
                                                            Integer.parseInt(fields[3]));
                                                }));
    }

    @ParameterizedTest(name = "{0} {1} {2}")
    @MethodSource("scenarios")
    void actualTransportBoundary(
            String mode, String action, String scenario, String rule, int count) throws Exception {
        Path root = Path.of("..").toAbsolutePath().normalize();
        var properties = new Properties();
        if (!scenario.equals("default")) {
            properties.setProperty(
                    "allow.mcp.resources",
                    McpOperations.resource("inventory", McpTransportApplication.URI));
            properties.setProperty(
                    "allow.mcp.prompts", McpOperations.prompt("inventory", "summarize"));
            properties.setProperty("allow.mcp.tools", "mcp:inventory/lookup");
        }
        properties.setProperty("deny.text", "secret-marker");
        properties.setProperty("detector.timeout.millis", "3000");
        Path config = directory.resolve("policy.properties");
        try (var writer = Files.newBufferedWriter(config)) {
            properties.store(writer, "Real MCP transport acceptance");
        }
        Path log = directory.resolve("process.log");
        Path journal = directory.resolve("requests.log");
        var process =
                new ProcessBuilder(
                                Path.of(System.getProperty("java.home"), "bin/java").toString(),
                                "-javaagent:"
                                        + root.resolve(
                                                "agent-security-javaagent/target/agent-security-javaagent.jar")
                                        + "="
                                        + config,
                                "-cp",
                                root.resolve("demo/target/test-classes")
                                        + java.io.File.pathSeparator
                                        + root.resolve("demo/target/agent-security-demo.jar"),
                                McpTransportApplication.class.getName(),
                                mode,
                                action,
                                scenario,
                                journal.toString())
                        .redirectErrorStream(true)
                        .redirectOutput(log.toFile())
                        .start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
            fail("MCP transport child timed out: " + Files.readString(log));
        }
        String output = Files.readString(log);
        assertEquals(0, process.exitValue(), output);
        assertTrue(output.contains("TRANSPORT_RESULT rule=" + rule + " calls=" + count), output);
        assertEquals(count, Files.exists(journal) ? Files.readAllLines(journal).size() : 0, output);
    }
}
