package io.agentsecurity.demo;

import com.sun.net.httpserver.HttpServer;
import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.mcp.client.DefaultMcpClient;
import dev.langchain4j.mcp.client.transport.McpTransport;
import dev.langchain4j.mcp.client.transport.http.StreamableHttpMcpTransport;
import dev.langchain4j.mcp.client.transport.stdio.StdioMcpTransport;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.delegation.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

/** 独立 JVM 中加载实际 Agent 和官方传输，服务端计数只包含业务请求。 */
public final class McpTransportApplication {
    public static final String URI = "docs://inventory/item-1";

    public static void main(String[] args) throws Exception {
        String mode = args[0];
        String action = args[1];
        String scenario = args[2];
        Path journal = Path.of(args[3]);
        HttpServer http = null;
        McpTransport transport;
        if (mode.equals("stdio")) {
            transport =
                    new StdioMcpTransport.Builder()
                            .command(
                                    List.of(
                                            Path.of(System.getProperty("java.home"), "bin/java")
                                                    .toString(),
                                            "-cp",
                                            System.getProperty("java.class.path"),
                                            McpProtocolServer.class.getName(),
                                            journal.toString(),
                                            scenario))
                            .build();
        } else {
            var server = new McpProtocolServer(journal, scenario);
            http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            http.createContext(
                    "/mcp",
                    exchange -> {
                        try (exchange) {
                            if (!exchange.getRequestMethod().equals("POST")) {
                                exchange.sendResponseHeaders(405, -1);
                                return;
                            }
                            String request =
                                    new String(
                                            exchange.getRequestBody().readNBytes(65536),
                                            StandardCharsets.UTF_8);
                            String reply = server.reply(request);
                            if (reply == null) {
                                exchange.sendResponseHeaders(202, -1);
                                return;
                            }
                            exchange.getResponseHeaders()
                                    .set(
                                            "Content-Type",
                                            mode.equals("sse")
                                                    ? "text/event-stream"
                                                    : "application/json");
                            byte[] body =
                                    (mode.equals("sse")
                                                    ? "event: message\ndata: " + reply + "\n\n"
                                                    : reply)
                                            .getBytes(StandardCharsets.UTF_8);
                            exchange.sendResponseHeaders(200, body.length);
                            exchange.getResponseBody().write(body);
                        } catch (Exception error) {
                            throw new java.io.IOException(error);
                        }
                    });
            http.start();
            transport =
                    new StreamableHttpMcpTransport.Builder()
                            .url("http://127.0.0.1:" + http.getAddress().getPort() + "/mcp")
                            .timeout(Duration.ofSeconds(5))
                            .build();
        }
        try (var client =
                DefaultMcpClient.builder()
                        .key(scenario.equals("server") ? "other" : "inventory")
                        .transport(transport)
                        .protocolVersion("2025-11-25")
                        .toolExecutionTimeout(Duration.ofSeconds(2))
                        .resourcesTimeout(Duration.ofSeconds(2))
                        .promptsTimeout(Duration.ofSeconds(2))
                        .build()) {
            Callable<Object> operation =
                    switch (action) {
                        case "listTools" -> client::listTools;
                        case "listResources" -> client::listResources;
                        case "listResourceTemplates" -> client::listResourceTemplates;
                        case "listPrompts" -> client::listPrompts;
                        case "instructions" -> client::instructions;
                        case "resource" ->
                                () ->
                                        client.readResource(
                                                scenario.equals("target")
                                                        ? "docs://inventory/item-2"
                                                        : URI);
                        case "prompt" ->
                                () ->
                                        client.getPrompt(
                                                scenario.equals("target") ? "other" : "summarize",
                                                Map.of(
                                                        "q",
                                                        scenario.equals("input")
                                                                ? "secret-marker"
                                                                : "safe"));
                        case "tool" ->
                                () ->
                                        client.executeToolAsync(
                                                        ToolExecutionRequest.builder()
                                                                .name("lookup")
                                                                .arguments("{}")
                                                                .build(),
                                                        null)
                                                .join();
                        default -> throw new IllegalArgumentException("Unknown action");
                    };
            if (scenario.equals("cached")) {
                client.listTools();
            }
            String rule = "allow";
            long queryStarted = System.nanoTime();
            try {
                if (scenario.equals("delegation") || scenario.equals("cached")) {
                    var grant = AgentGrant.tools(Set.of(), Set.of("lookup"));
                    try (var runtime =
                                    new AgentRuntime(
                                            List.of(new AgentDefinition("reader", grant, Set.of())),
                                            AgentRuntimeLimits.defaults(),
                                            (event, decision) -> {});
                            var root =
                                    runtime.startRoot(
                                            "reader",
                                            SecurityContext.authenticated(
                                                    "tenant", "user", Set.of()),
                                            grant,
                                            Duration.ofMinutes(1))) {
                        root.call(operation);
                    }
                } else {
                    Object result = operation.call();
                    if (scenario.equals("paged-ok")
                            && (!(result instanceof List<?> list) || list.size() != 2)) {
                        throw new AssertionError("Expected two aggregated items");
                    }
                }
            } catch (Exception failure) {
                Throwable cause = failure;
                while (cause.getCause() != null) {
                    cause = cause.getCause();
                }
                if (!(cause instanceof SecurityBlockedException denied)) {
                    throw new AssertionError("Unexpected transport failure", failure);
                }
                rule = denied.ruleId();
            }
            if (scenario.equals("paged-timeout")) {
                long elapsedMillis = (System.nanoTime() - queryStarted) / 1_000_000;
                if (elapsedMillis < 1000 || elapsedMillis > 1550) {
                    throw new AssertionError(
                            "Unexpected total deadline duration: " + elapsedMillis);
                }
            }
            if (scenario.equals("wire")) {
                try {
                    operation.call();
                    throw new AssertionError("Poisoned transport unexpectedly reused");
                } catch (SecurityBlockedException expected) {
                    if (!expected.ruleId().equals("mcp-response-limit")) {
                        throw expected;
                    }
                } catch (java.util.concurrent.CompletionException expected) {
                    if (!(expected.getCause() instanceof SecurityBlockedException denied)
                            || !denied.ruleId().equals("mcp-response-limit")) {
                        throw expected;
                    }
                }
            }
            if (scenario.equals("paged-pages")) {
                try {
                    operation.call();
                    throw new AssertionError("Expected a fresh pagination budget rejection");
                } catch (SecurityBlockedException denied) {
                    if (!denied.ruleId().equals("mcp-pagination-pages")) {
                        throw denied;
                    }
                }
            }
            var metrics = io.agentsecurity.core.health.McpDiagnostics.global().snapshot();
            if (scenario.equals("wire")) {
                var reason =
                        mode.equals("stdio")
                                ? io.agentsecurity.core.health.McpDiagnostics.Limit.STDIO_LINE_BYTES
                                : io.agentsecurity.core.health.McpDiagnostics.Limit
                                        .HTTP_RESPONSE_BYTES;
                if (metrics.limits().get(reason) != 1
                        || metrics.transportFailures() != 1
                        || metrics.failedStateChecks() < 1) {
                    throw new AssertionError("Capacity diagnostics incorrect: " + metrics);
                }
            }
            if (scenario.equals("cached") && metrics.paginationStarted() != 1) {
                throw new AssertionError("Cache incorrectly fetched again");
            }
            if (scenario.startsWith("paged-")) {
                long attempts = scenario.equals("paged-pages") ? 2 : 1;
                long completed = scenario.equals("paged-ok") ? 1 : 0;
                long limits = metrics.limits().values().stream().mapToLong(Long::longValue).sum();
                if (metrics.paginationStarted() != attempts
                        || metrics.paginationCompleted() != completed
                        || metrics.paginationFailed() != attempts - completed
                        || limits != attempts - completed
                        || metrics.transportFailures() != 0) {
                    throw new AssertionError("Pagination diagnostics incorrect: " + metrics);
                }
                if (scenario.equals("paged-ok")
                        && (metrics.pagesAccepted() != 2 || metrics.itemsAccepted() != 2)) {
                    throw new AssertionError("Pagination totals incorrect");
                }
            }
            long count = Files.exists(journal) ? Files.readAllLines(journal).size() : 0;
            System.out.println("TRANSPORT_RESULT rule=" + rule + " calls=" + count);
        } finally {
            if (http != null) {
                http.stop(0);
            }
        }
    }
}
