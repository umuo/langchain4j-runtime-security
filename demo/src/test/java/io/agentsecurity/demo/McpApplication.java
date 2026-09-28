package io.agentsecurity.demo;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.mcp.client.DefaultMcpClient;
import dev.langchain4j.mcp.client.McpCallContext;
import dev.langchain4j.mcp.client.transport.McpOperationHandler;
import dev.langchain4j.mcp.client.transport.McpTransport;
import dev.langchain4j.mcp.protocol.McpClientMessage;
import dev.langchain4j.mcp.protocol.McpInitializeRequest;
import io.agentsecurity.core.*;
import io.agentsecurity.core.delegation.*;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/** 真实 MCP 客户端验收入口，只有传输替换为可计数的内存实现。 */
public final class McpApplication {
    public static void main(String[] args) throws Exception {
        String scenario = args[0];
        var transport = new Transport(scenario);
        String key =
                scenario.equals("server")
                        ? "other"
                        : scenario.equals("invalid") ? "bad/key" : "inventory";
        try (var client =
                DefaultMcpClient.builder()
                        .key(key)
                        .transport(transport)
                        .protocolVersion("2025-11-25")
                        .build()) {
            String tool = scenario.equals("tool") ? "delete" : "lookup";
            var request =
                    ToolExecutionRequest.builder()
                            .name(tool)
                            .arguments(
                                    scenario.equals("input") ? "{\"q\":\"secret-marker\"}" : "{}")
                            .build();
            Throwable failure = null;
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
                        root.call(() -> client.executeTool(request));
                    }
                } else if (scenario.startsWith("async")) {
                    CompletableFuture<?> future;
                    if (scenario.equals("async-ended")) {
                        var grant = AgentGrant.tools(Set.of(), Set.of("mcp:inventory/lookup"));
                        try (var runtime =
                                        new AgentRuntime(
                                                List.of(
                                                        new AgentDefinition(
                                                                "reader", grant, Set.of())),
                                                AgentRuntimeLimits.defaults(),
                                                (event, decision) -> {});
                                var root =
                                        runtime.startRoot(
                                                "reader",
                                                SecurityContext.authenticated(
                                                        "tenant", "user", Set.of()),
                                                grant,
                                                Duration.ofMinutes(1))) {
                            future = root.call(() -> client.executeToolAsync(request, null));
                        }
                    } else {
                        future = client.executeToolAsync(request, null);
                    }
                    if (transport.pending != null) {
                        Thread thread =
                                new Thread(() -> transport.pending.complete(transport.response()));
                        thread.start();
                        thread.join();
                    }
                    future.join();
                } else {
                    client.executeTool(request);
                }
            } catch (Exception error) {
                failure = error;
                while (failure.getCause() != null) {
                    failure = failure.getCause();
                }
            }
            String rule =
                    failure instanceof SecurityBlockedException denied
                            ? denied.ruleId()
                            : failure == null ? "allow" : failure.getClass().getName();
            System.out.println("MCP_RESULT rule=" + rule + " calls=" + transport.calls);
            if (failure != null && !(failure instanceof SecurityBlockedException)) {
                throw new AssertionError("Unexpected failure", failure);
            }
        }
    }

    public static final class Transport implements McpTransport {
        private final String scenario;
        private int calls;
        private CompletableFuture<String> pending;

        Transport(String scenario) {
            this.scenario = scenario;
        }

        @Override
        public void start(McpOperationHandler handler) {}

        @Override
        public void onFailure(Runnable callback) {}

        @Override
        public void checkHealth() {}

        @Override
        public void close() {}

        @Override
        public void sendMessage(McpClientMessage message) {}

        @Override
        public void sendMessage(McpCallContext context) {}

        @Override
        public CompletableFuture<String> sendInitializeRequest(McpInitializeRequest request) {
            return CompletableFuture.completedFuture(
                    "{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"fixture\",\"version\":\"1\"}}}");
        }

        @Override
        public CompletableFuture<String> sendRequest(McpCallContext context) {
            calls++;
            if (scenario.startsWith("async")) {
                pending = new CompletableFuture<>();
                return pending;
            }
            return CompletableFuture.completedFuture(response());
        }

        private String response() {
            String value = scenario.contains("output") ? "secret-marker" : "safe";
            String metadata =
                    scenario.equals("metadata") ? ",\"_meta\":{\"private\":\"hidden\"}" : "";
            return "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\""
                    + value
                    + "\"}]"
                    + metadata
                    + "}}";
        }
    }
}
