package io.agentsecurity.agent.bridge;

import io.agentsecurity.core.ResourceRef;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import io.agentsecurity.core.SecurityEvent;
import io.agentsecurity.core.mcp.McpOperations;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** 资源和提示词的有界文本适配，拒绝未知内容类型，不调用第三方对象的 toString。 */
public final class McpContentBridge {
    private static final int MAX_ITEMS = 128;
    private static final int MAX_ARGUMENTS = 64;

    private McpContentBridge() {}

    /** 固定入口身份和资源；出口不重新读取可变参数或客户端 key。 */
    public record Boundary(String operation, String uri, SecurityContext context) {}

    public static Boundary before(Object client, String method, Object[] arguments) {
        try {
            return beforeInternal(client, method, arguments);
        } catch (RuntimeException failure) {
            McpFailureBridge.record(
                    failure,
                    method,
                    io.agentsecurity.core.diagnostics.FailureRecord.Stage.MCP_INPUT,
                    SecurityContexts.current());
            throw failure;
        }
    }

    private static Boundary beforeInternal(Object client, String method, Object[] arguments) {
        String server = McpBridge.server(client);
        String target = text(arguments[0]);
        boolean resource = method.equals("readResource");
        String operation;
        try {
            operation =
                    resource
                            ? McpOperations.resource(server, target)
                            : McpOperations.prompt(server, target);
        } catch (IllegalArgumentException error) {
            throw new SecurityBlockedException("invalid-mcp-target");
        }
        StringBuilder content = new StringBuilder();
        Bridge.append(content, target);
        if (!resource) {
            Object input = arguments[1];
            // 提示词参数仅支持字符串键值，不隐式序列化任意宿主对象。
            if (input != null) {
                if (!(input instanceof Map<?, ?> map) || map.size() > MAX_ARGUMENTS) {
                    throw new SecurityBlockedException("mcp-prompt-arguments");
                }
                int count = 0;
                for (var entry : map.entrySet()) {
                    if (++count > MAX_ARGUMENTS) {
                        throw new SecurityBlockedException("mcp-prompt-arguments");
                    }
                    Bridge.append(content, text(entry.getKey()));
                    Bridge.append(content, text(entry.getValue()));
                }
            }
        }
        var boundary =
                new Boundary(operation, resource ? target : null, SecurityContexts.current());
        check(
                client,
                boundary,
                resource
                        ? SecurityEvent.Phase.MCP_RESOURCE_INPUT
                        : SecurityEvent.Phase.MCP_PROMPT_INPUT,
                content.toString());
        return boundary;
    }

    public static void after(Object client, Boundary boundary, Object result) {
        try {
            afterInternal(client, boundary, result);
        } catch (RuntimeException failure) {
            McpFailureBridge.record(
                    failure,
                    boundary.uri() == null ? "getPrompt" : "readResource",
                    io.agentsecurity.core.diagnostics.FailureRecord.Stage.MCP_OUTPUT,
                    boundary.context());
            throw failure;
        }
    }

    private static void afterInternal(Object client, Boundary boundary, Object result) {
        io.agentsecurity.agent.mcp.McpResponseLimits.check(client);
        boolean resource = boundary.uri() != null;
        shape(result, resource ? "McpReadResourceResult" : "McpGetPromptResult");
        StringBuilder content = new StringBuilder();
        if (resource) {
            for (Object item : items(Bridge.call(result, "contents"))) {
                shape(item, "McpTextResourceContents");
                String uri = text(Bridge.call(item, "uri"));
                if (!boundary.uri().equals(uri)) {
                    throw new SecurityBlockedException("mcp-resource-uri-mismatch");
                }
                Bridge.append(content, uri);
                optional(content, Bridge.call(item, "mimeType"));
                Bridge.append(content, text(Bridge.call(item, "text")));
            }
        } else {
            optional(content, Bridge.call(result, "description"));
            for (Object message : items(Bridge.call(result, "messages"))) {
                shape(message, "McpPromptMessage");
                Object role = Bridge.call(message, "role");
                if (!(role instanceof Enum<?> value)
                        || !(value.name().equals("USER") || value.name().equals("ASSISTANT"))) {
                    throw new SecurityBlockedException("unsupported-mcp-content");
                }
                Object item = Bridge.call(message, "content");
                shape(item, "McpTextContent");
                Bridge.append(content, value.name());
                Bridge.append(content, text(Bridge.call(item, "text")));
            }
        }
        try (var scope = SecurityContexts.restore(boundary.context())) {
            check(
                    client,
                    boundary,
                    resource
                            ? SecurityEvent.Phase.MCP_RESOURCE_OUTPUT
                            : SecurityEvent.Phase.MCP_PROMPT_OUTPUT,
                    content.toString());
        }
    }

    private static void check(
            Object client, Boundary boundary, SecurityEvent.Phase phase, String text) {
        Bridge.check(
                client,
                new SecurityEvent(
                        UUID.randomUUID(),
                        phase,
                        boundary.operation(),
                        text,
                        boundary.context(),
                        boundary.uri() == null
                                ? null
                                : new ResourceRef("mcp-resource", boundary.uri())));
    }

    private static List<?> items(Object value) {
        if (!(value instanceof List<?> list) || list.size() > MAX_ITEMS) {
            throw new SecurityBlockedException("mcp-content-limit");
        }
        return list;
    }

    private static void shape(Object value, String type) {
        if (value == null
                || !value.getClass().getName().equals("dev.langchain4j.mcp.client." + type)) {
            throw new SecurityBlockedException("unsupported-mcp-content");
        }
    }

    private static String text(Object value) {
        if (!(value instanceof String text)) {
            throw new SecurityBlockedException("adapter-shape-error");
        }
        return text;
    }

    private static void optional(StringBuilder output, Object value) {
        if (value != null) {
            Bridge.append(output, text(value));
        }
    }
}
