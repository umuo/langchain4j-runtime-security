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
                        .build()) {
            Callable<Object> operation =
                    switch (action) {
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
            String rule = "allow";
            try {
                if (scenario.equals("delegation")) {
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
                    operation.call();
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
            long count = Files.exists(journal) ? Files.readAllLines(journal).size() : 0;
            System.out.println("TRANSPORT_RESULT rule=" + rule + " calls=" + count);
        } finally {
            if (http != null) {
                http.stop(0);
            }
        }
    }
}
