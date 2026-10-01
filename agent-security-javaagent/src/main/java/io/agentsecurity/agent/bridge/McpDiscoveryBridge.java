package io.agentsecurity.agent.bridge;

import io.agentsecurity.agent.mcp.McpResponseLimits;
import io.agentsecurity.core.*;
import io.agentsecurity.core.mcp.McpOperations;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** 发现权限独立于执行权限；返回整批扫描，拒绝隐藏元数据和未知形状。 */
public final class McpDiscoveryBridge {
    private McpDiscoveryBridge() {}

    public record Boundary(String operation, String method, SecurityContext context) {}

    public static Boundary before(Object client, String method) {
        var boundary =
                new Boundary(
                        McpOperations.discovery(McpBridge.server(client), method),
                        method,
                        SecurityContexts.current());
        check(client, boundary, SecurityEvent.Phase.MCP_DISCOVERY_INPUT, "");
        return boundary;
    }

    public static void after(Object client, Boundary boundary, Object result) {
        McpResponseLimits.check(client);
        StringBuilder text = new StringBuilder();
        if (boundary.method().equals("instructions")) {
            append(text, result);
        } else {
            for (Object item : list(result)) {
                String method = boundary.method();
                if (method.equals("listTools")) {
                    shape(item, "dev.langchain4j.agent.tool.ToolSpecification");
                    empty(Bridge.call(item, "metadata"));
                    schema(text, Bridge.call(item, "parameters"), 0, new int[] {0});
                } else {
                    shape(
                            item,
                            "dev.langchain4j.mcp.client."
                                    + switch (method) {
                                        case "listResources" -> "McpResource";
                                        case "listResourceTemplates" -> "McpResourceTemplate";
                                        case "listPrompts" -> "McpPrompt";
                                        default ->
                                                throw new SecurityBlockedException(
                                                        "unsupported-mcp-content");
                                    });
                    empty(Bridge.call(item, "metadata"));
                    empty(Bridge.call(item, "icons"));
                    if (method.equals("listPrompts")) {
                        Object arguments = Bridge.call(item, "arguments");
                        if (arguments != null) {
                            for (Object argument : list(arguments)) {
                                shape(argument, "dev.langchain4j.mcp.client.McpPromptArgument");
                                append(text, Bridge.call(argument, "name"));
                                append(text, Bridge.call(argument, "description"));
                            }
                        }
                    } else {
                        append(
                                text,
                                Bridge.call(
                                        item,
                                        method.equals("listResources") ? "uri" : "uriTemplate"));
                        append(text, Bridge.call(item, "mimeType"));
                    }
                }
                append(text, Bridge.call(item, "name"));
                append(text, Bridge.call(item, "description"));
            }
        }
        try (var scope = SecurityContexts.restore(boundary.context())) {
            check(client, boundary, SecurityEvent.Phase.MCP_DISCOVERY_OUTPUT, text.toString());
        }
    }

    private static void schema(StringBuilder text, Object value, int depth, int[] nodes) {
        if (value == null) {
            return;
        }
        if (depth > 16 || ++nodes[0] > 1024) {
            throw new SecurityBlockedException("mcp-schema-limit");
        }
        String type = value.getClass().getSimpleName();
        if (!Set.of(
                        "JsonObjectSchema",
                        "JsonArraySchema",
                        "JsonAnyOfSchema",
                        "JsonReferenceSchema",
                        "JsonEnumSchema",
                        "JsonStringSchema",
                        "JsonIntegerSchema",
                        "JsonNumberSchema",
                        "JsonBooleanSchema",
                        "JsonNullSchema")
                .contains(type)) {
            throw new SecurityBlockedException("unsupported-mcp-content");
        }
        shape(value, "dev.langchain4j.model.chat.request.json." + type);
        append(text, Bridge.call(value, "description"));
        switch (type) {
            case "JsonObjectSchema" -> {
                for (String field : List.of("properties", "definitions")) {
                    Object entries = Bridge.call(value, field);
                    if (entries != null) {
                        if (!(entries instanceof Map<?, ?> map) || map.size() > 128) {
                            throw new SecurityBlockedException("mcp-schema-limit");
                        }
                        for (var entry : map.entrySet()) {
                            append(text, entry.getKey());
                            schema(text, entry.getValue(), depth + 1, nodes);
                        }
                    }
                }
                strings(text, Bridge.call(value, "required"));
            }
            case "JsonArraySchema" -> schema(text, Bridge.call(value, "items"), depth + 1, nodes);
            case "JsonAnyOfSchema" -> {
                for (Object child : list(Bridge.call(value, "anyOf"))) {
                    schema(text, child, depth + 1, nodes);
                }
            }
            case "JsonEnumSchema" -> strings(text, Bridge.call(value, "enumValues"));
            case "JsonReferenceSchema" -> append(text, Bridge.call(value, "reference"));
            default -> {
                /* 其余受支持类型只有描述字符串。 */
            }
        }
    }

    private static void strings(StringBuilder text, Object value) {
        if (value != null) {
            for (Object item : list(value)) {
                append(text, item);
            }
        }
    }

    private static void empty(Object value) {
        if (value == null
                || value instanceof Map<?, ?> map && map.isEmpty()
                || value instanceof List<?> list && list.isEmpty()) {
            return;
        }
        throw new SecurityBlockedException("mcp-discovery-metadata-unsupported");
    }

    private static List<?> list(Object value) {
        if (!(value instanceof List<?> list) || list.size() > 128) {
            throw new SecurityBlockedException("mcp-content-limit");
        }
        return list;
    }

    private static void append(StringBuilder text, Object value) {
        if (value == null) {
            return;
        }
        if (!(value instanceof String string)) {
            throw new SecurityBlockedException("adapter-shape-error");
        }
        Bridge.append(text, string);
    }

    private static void shape(Object value, String name) {
        if (value == null || !value.getClass().getName().equals(name)) {
            throw new SecurityBlockedException("unsupported-mcp-content");
        }
    }

    private static void check(
            Object client, Boundary boundary, SecurityEvent.Phase phase, String text) {
        Bridge.check(
                client,
                new SecurityEvent(
                        UUID.randomUUID(), phase, boundary.operation(), text, boundary.context()));
    }
}
