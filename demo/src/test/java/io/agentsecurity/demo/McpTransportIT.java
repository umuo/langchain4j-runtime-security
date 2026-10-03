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

    @org.junit.jupiter.api.RepeatedTest(20)
    void repeatedColdStartInputRejection() throws Exception {
        actualTransportBoundary("sse", "prompt", "input", "denied-text", 0);
    }

    static Stream<Arguments> scenarios() {
        var baseline =
                Stream.of("http", "sse", "stdio")
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
                                                        "tool,output,denied-text,1",
                                                        "listTools,allow,allow,1",
                                                        "listTools,protocol-error,protocol-error,1",
                                                        "listResources,protocol-error,protocol-error,1",
                                                        "listResourceTemplates,protocol-error,protocol-error,1",
                                                        "listPrompts,protocol-error,protocol-error,1",
                                                        "listTools,default,mcp-discovery-not-allowed,0",
                                                        "listResources,allow,allow,1",
                                                        "listResources,default,mcp-discovery-not-allowed,0",
                                                        "listResourceTemplates,allow,allow,1",
                                                        "listResourceTemplates,default,mcp-discovery-not-allowed,0",
                                                        "listPrompts,allow,allow,1",
                                                        "listPrompts,default,mcp-discovery-not-allowed,0",
                                                        "instructions,allow,allow,0",
                                                        "instructions,default,mcp-discovery-not-allowed,0",
                                                        "instructions,output,denied-text,0",
                                                        "listTools,schema,denied-text,1",
                                                        "listPrompts,schema,denied-text,1",
                                                        "listResources,metadata,mcp-discovery-metadata-unsupported,1",
                                                        "listTools,limit,mcp-pagination-items,1",
                                                        "listTools,cached,agent-tool-denied,1",
                                                        "tool,wire,mcp-response-limit,1",
                                                        "listTools,paged-ok,allow,2",
                                                        "listTools,paged-timeout,mcp-pagination-timeout,2",
                                                        "listResources,paged-timeout,mcp-pagination-timeout,2",
                                                        "listResourceTemplates,paged-timeout,mcp-pagination-timeout,2",
                                                        "listPrompts,paged-timeout,mcp-pagination-timeout,2",
                                                        "listResources,paged-ok,allow,2",
                                                        "listResourceTemplates,paged-ok,allow,2",
                                                        "listPrompts,paged-ok,allow,2",
                                                        "listTools,paged-pages,mcp-pagination-pages,4",
                                                        "listTools,paged-items,mcp-pagination-items,2",
                                                        "listTools,paged-bytes,mcp-pagination-bytes,2",
                                                        "listTools,paged-cursor,mcp-pagination-cursor,2",
                                                        "listTools,paged-long-cursor,mcp-pagination-cursor,1",
                                                        "listTools,paged-empty,mcp-pagination-pages,2")
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
        var auth =
                Stream.of("http", "sse")
                        .flatMap(
                                mode ->
                                        List.of(
                                                        "auth-ok,allow,1",
                                                        "auth-disconnect,mcp-http-transport-failed,1",
                                                        "auth-401,mcp-http-auth-failed,1",
                                                        "auth-403,mcp-http-auth-failed,1",
                                                        "auth-404,mcp-http-session-expired,1",
                                                        "auth-503,mcp-http-unavailable,1",
                                                        "auth-redirect,mcp-http-redirect,1",
                                                        "auth-missing,mcp-http-auth-required,0",
                                                        "auth-rotate,mcp-http-credential-changed,0",
                                                        "auth-malformed,mcp-http-auth-required,0")
                                                .stream()
                                                .map(
                                                        value -> {
                                                            var fields = value.split(",");
                                                            return Arguments.of(
                                                                    mode,
                                                                    "listTools",
                                                                    fields[0],
                                                                    fields[1],
                                                                    Integer.parseInt(fields[2]));
                                                        }));
        return Stream.concat(baseline, auth);
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
            properties.setProperty(
                    "allow.mcp.discovery",
                    Stream.of(
                                    "listTools",
                                    "listResources",
                                    "listResourceTemplates",
                                    "listPrompts",
                                    "instructions")
                            .map(method -> McpOperations.discovery("inventory", method))
                            .collect(java.util.stream.Collectors.joining(",")));
        }
        properties.setProperty("deny.text", "secret-marker");
        if (scenario.startsWith("auth-")) {
            properties.setProperty("mcp.http.require.bearer", "true");
        }
        if (scenario.equals("wire")) {
            properties.setProperty("mcp.max.response.bytes", "1024");
        }
        if (scenario.equals("paged-pages") || scenario.equals("paged-empty")) {
            properties.setProperty("mcp.pagination.max.pages", "2");
        }
        if (scenario.equals("paged-items")) {
            properties.setProperty("mcp.pagination.max.items", "1");
        }
        if (scenario.equals("paged-bytes")) {
            properties.setProperty("mcp.pagination.max.json.bytes", "1024");
        }
        if (scenario.equals("paged-timeout")) {
            properties.setProperty("mcp.pagination.timeout.ms", "1200");
        }
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
