package io.agentsecurity.agent.bridge;

import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityEvent;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;

/** MCP 工具的独立边界：使用宿主配置的客户端 key 和物理工具名，不采用模型生成的别名。 */
public final class McpBridge {
    public static final String CLIENT = "dev.langchain4j.mcp.client.McpClient";
    private static final ClassValue<Boolean> VERSIONS =
            new ClassValue<>() {
                @Override
                protected Boolean computeValue(Class<?> type) {
                    try (var input =
                            type.getClassLoader()
                                    .getResourceAsStream(
                                            "META-INF/maven/dev.langchain4j/langchain4j-mcp/pom.properties")) {
                        if (input == null) {
                            throw new SecurityBlockedException("unsupported-mcp-version");
                        }
                        var properties = new Properties();
                        properties.load(input);
                        if (!"1.20.0-beta30".equals(properties.getProperty("version"))) {
                            throw new SecurityBlockedException("unsupported-mcp-version");
                        }
                        return true;
                    } catch (java.io.IOException | NullPointerException error) {
                        throw new SecurityBlockedException("unsupported-mcp-version");
                    }
                }
            };

    private McpBridge() {}

    static String server(Object client) {
        Bridge.verifyBoundary(client);
        VERSIONS.get(client.getClass());
        io.agentsecurity.agent.mcp.McpResponseLimits.check(client);
        return name(Bridge.call(client, "key"));
    }

    public static String before(Object client, Object request) {
        Bridge.verifyBoundary(request);
        VERSIONS.get(client.getClass());
        io.agentsecurity.agent.mcp.McpResponseLimits.check(client);
        String operation =
                "mcp:"
                        + name(Bridge.call(client, "key"))
                        + "/"
                        + name(Bridge.call(request, "name"));
        Object arguments = Bridge.call(request, "arguments");
        if (arguments != null && !(arguments instanceof String)) {
            throw new SecurityBlockedException("adapter-shape-error");
        }
        Bridge.check(
                request,
                new SecurityEvent(
                        SecurityEvent.Phase.MCP_TOOL_INPUT, operation, (String) arguments));
        return operation;
    }

    public static void after(Object client, Object request, String operation, Object result) {
        io.agentsecurity.agent.mcp.McpResponseLimits.check(client);
        if (result == null) {
            throw new SecurityBlockedException("null-result");
        }
        // 元数据可包含任意嵌套对象；本轮不向应用交付未经检测的隐藏内容。
        Object attributes = Bridge.call(result, "attributes");
        if (!(attributes instanceof Map<?, ?> map) || !map.isEmpty()) {
            throw new SecurityBlockedException("mcp-result-attributes-unsupported");
        }
        Object text = Bridge.call(result, "resultText");
        if (!(text instanceof String value)) {
            throw new SecurityBlockedException("adapter-shape-error");
        }
        Bridge.check(
                request, new SecurityEvent(SecurityEvent.Phase.MCP_TOOL_OUTPUT, operation, value));
    }

    public static CompletableFuture<?> guardFuture(
            Object client,
            Object request,
            String operation,
            CompletableFuture<?> future,
            SecurityContext context) {
        return RagBridge.mapFuture(
                future,
                context,
                result -> {
                    after(client, request, operation, result);
                    return result;
                });
    }

    private static String name(Object value) {
        if (!(value instanceof String name) || !name.matches("[a-zA-Z0-9_.-]{1,100}")) {
            throw new SecurityBlockedException("invalid-mcp-name");
        }
        return name;
    }
}
