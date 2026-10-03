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
        var initializations = new java.util.concurrent.atomic.AtomicInteger();
        var redirects = new java.util.concurrent.atomic.AtomicInteger();
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
                            String rpcMethod =
                                    new com.fasterxml.jackson.databind.ObjectMapper()
                                            .readTree(request)
                                            .path("method")
                                            .asText();
                            if (rpcMethod.equals("initialize")) {
                                initializations.incrementAndGet();
                            }
                            if (scenario.startsWith("auth-")) {
                                if (!"Bearer fixture-token"
                                        .equals(
                                                exchange.getRequestHeaders()
                                                        .getFirst("Authorization"))) {
                                    throw new AssertionError("Incorrect request credentials");
                                }
                                if (rpcMethod.equals("tools/list")
                                        && scenario.equals("auth-disconnect")) {
                                    Files.writeString(
                                            journal,
                                            rpcMethod + "\n",
                                            java.nio.file.StandardOpenOption.CREATE,
                                            java.nio.file.StandardOpenOption.APPEND);
                                    exchange.sendResponseHeaders(200, 100);
                                    exchange.close();
                                    return;
                                }
                                int status =
                                        switch (scenario) {
                                            case "auth-401" -> 401;
                                            case "auth-403" -> 403;
                                            case "auth-404" -> 404;
                                            case "auth-503" -> 503;
                                            case "auth-redirect" -> 307;
                                            default -> 200;
                                        };
                                if (rpcMethod.equals("tools/list") && status != 200) {
                                    Files.writeString(
                                            journal,
                                            rpcMethod + "\n",
                                            java.nio.file.StandardOpenOption.CREATE,
                                            java.nio.file.StandardOpenOption.APPEND);
                                    if (status == 307) {
                                        exchange.getResponseHeaders()
                                                .set("Location", "/redirect-target");
                                    }
                                    exchange.sendResponseHeaders(status, -1);
                                    return;
                                }
                            }
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
            http.createContext(
                    "/redirect-target",
                    exchange -> {
                        redirects.incrementAndGet();
                        exchange.sendResponseHeaders(200, -1);
                        exchange.close();
                    });
            http.start();
            var credentialCalls = new java.util.concurrent.atomic.AtomicInteger();
            transport =
                    new StreamableHttpMcpTransport.Builder()
                            .customHeaders(
                                    () -> {
                                        if (!scenario.startsWith("auth-")) {
                                            return Map.of();
                                        }
                                        int request = credentialCalls.incrementAndGet();
                                        if (request > 2 && scenario.equals("auth-missing")) {
                                            return Map.of();
                                        }
                                        String token =
                                                request > 2 && scenario.equals("auth-rotate")
                                                        ? "Bearer changed-token"
                                                        : request > 2
                                                                        && scenario.equals(
                                                                                "auth-malformed")
                                                                ? "Basic invalid"
                                                                : "Bearer fixture-token";
                                        return Map.of("Authorization", token);
                                    })
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
                if (cause instanceof SecurityBlockedException denied) {
                    rule = denied.ruleId();
                } else if (scenario.equals("protocol-error")
                        && failure instanceof RuntimeException) {
                    rule = "protocol-error";
                } else {
                    throw new AssertionError("Unexpected transport failure", failure);
                }
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
            if (scenario.startsWith("auth-") && !rule.equals("allow")) {
                try {
                    operation.call();
                    throw new AssertionError("Failed HTTP client reused");
                } catch (SecurityBlockedException expected) {
                    if (!expected.ruleId().equals(rule)) {
                        throw expected;
                    }
                }
            }
            if (scenario.startsWith("auth-")
                    && (initializations.get() != 1 || redirects.get() != 0)) {
                throw new AssertionError("Unexpected reinitialization or credential redirect");
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
            var failures = io.agentsecurity.core.diagnostics.FailureDiagnostics.global().drain(256);
            if (rule.equals("protocol-error")) {
                // 官方无参方法可转调带 InvocationContext 的重载；普通异常按边界记录。
                int expectedFailures = action.equals("listPrompts") ? 1 : 2;
                if (failures.size() != expectedFailures
                        || failures.stream()
                                .anyMatch(
                                        item ->
                                                item.category()
                                                                != io.agentsecurity.core.diagnostics
                                                                        .FailureRecord.Category
                                                                        .EXECUTION_FAILURE
                                                        || item.stage()
                                                                != io.agentsecurity.core.diagnostics
                                                                        .FailureRecord.Stage
                                                                        .MCP_EXECUTION
                                                        || item.boundary()
                                                                != io.agentsecurity.core.diagnostics
                                                                        .FailureRecord.Boundary
                                                                        .MCP_DISCOVERY)
                        || failures.toString().contains("secret-server-failure")) {
                    throw new AssertionError("Unsafe or missing execution failure record");
                }
            } else if (!rule.equals("allow")) {
                String fingerprint =
                        io.agentsecurity.core.diagnostics.FailureDiagnostics.fingerprint(rule);
                var diagnosed =
                        failures.stream()
                                .filter(item -> fingerprint.equals(item.ruleFingerprint()))
                                .toList();
                if (diagnosed.isEmpty()) {
                    throw new AssertionError("Missing correlated failure: " + rule);
                }
                if (scenario.equals("delegation")
                        && diagnosed.stream().anyMatch(item -> item.invocationId() == null)) {
                    throw new AssertionError("Missing delegated invocation identity");
                }
                if (scenario.equals("paged-timeout")
                        && diagnosed.stream()
                                .anyMatch(
                                        item ->
                                                item.category()
                                                                != io.agentsecurity.core.diagnostics
                                                                        .FailureRecord.Category
                                                                        .TIMEOUT
                                                        || item.stage()
                                                                != io.agentsecurity.core.diagnostics
                                                                        .FailureRecord.Stage
                                                                        .MCP_EXECUTION)) {
                    throw new AssertionError("Incorrect deadline failure stage");
                }
            } else if (!failures.isEmpty()) {
                throw new AssertionError("Unexpected failure diagnostic");
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
