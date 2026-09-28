package io.agentsecurity.core;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

/** 确定性的本地工具、检索器、操作权限与字面内容规则；字面匹配不等于语义注入检测。 */
public final class LocalPolicy implements Detector {

    private final Set<String> deniedTools;

    private final Set<String> allowedTools;

    private final Set<String> allowedRetrievers;

    private final Set<String> allowedMcpTools;

    private final java.util.Map<SecurityEvent.Phase, String> memoryPermissions;

    private final List<String> deniedText;

    private final int maxChars;

    private final boolean requireAgent;

    public LocalPolicy(Properties properties) {
        Set<String> known =
                Set.of(
                        "agent.context.required",
                        "deny.tools",
                        "allow.tools",
                        "allow.mcp.tools",
                        "allow.retrievers",
                        "deny.text",
                        "max.text.chars",
                        "memory.read.permission",
                        "memory.write.permission",
                        "memory.delete.permission");
        for (String key : properties.stringPropertyNames()) {
            if (!known.contains(key)) {
                throw new IllegalArgumentException("Unknown policy property: " + key);
            }
        }
        String require = properties.getProperty("agent.context.required", "false");
        if (!require.equals("true") && !require.equals("false")) {
            throw new IllegalArgumentException("Invalid agent.context.required");
        }
        requireAgent = Boolean.parseBoolean(require);
        deniedTools = Set.copyOf(split(properties.getProperty("deny.tools", "")));
        allowedTools =
                properties.containsKey("allow.tools")
                        ? Set.copyOf(split(properties.getProperty("allow.tools")))
                        : null;
        allowedRetrievers =
                properties.containsKey("allow.retrievers")
                        ? Set.copyOf(split(properties.getProperty("allow.retrievers")))
                        : null;
        allowedMcpTools = Set.copyOf(split(properties.getProperty("allow.mcp.tools", "")));
        if (allowedMcpTools.stream()
                .anyMatch(
                        name -> !name.matches("mcp:[a-zA-Z0-9_.-]{1,100}/[a-zA-Z0-9_.-]{1,100}"))) {
            throw new IllegalArgumentException("Invalid allow.mcp.tools");
        }
        var permissions =
                new java.util.EnumMap<SecurityEvent.Phase, String>(SecurityEvent.Phase.class);
        for (var entry :
                java.util.Map.of(
                                "read",
                                SecurityEvent.Phase.MEMORY_READ_INPUT,
                                "write",
                                SecurityEvent.Phase.MEMORY_WRITE,
                                "delete",
                                SecurityEvent.Phase.MEMORY_DELETE)
                        .entrySet()) {
            String value = properties.getProperty("memory." + entry.getKey() + ".permission");
            if (value != null) {
                if (!value.matches("[a-zA-Z0-9@._:-]{1,128}")) {
                    throw new IllegalArgumentException("Invalid memory permission");
                }
                permissions.put(entry.getValue(), value);
            }
        }
        memoryPermissions = java.util.Map.copyOf(permissions);
        deniedText =
                split(properties.getProperty("deny.text", "")).stream()
                        .map(s -> s.toLowerCase(Locale.ROOT))
                        .toList();
        maxChars = Integer.parseInt(properties.getProperty("max.text.chars", "100000"));
        if (maxChars < 1 || maxChars > 10000000) {
            throw new IllegalArgumentException("Invalid max.text.chars");
        }
    }

    private static List<String> split(String value) {
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    @Override
    public Decision evaluate(SecurityEvent event) {
        if (requireAgent && (event.context() == null || event.context().invocation() == null)) {
            return Decision.deny("missing-agent-context");
        }
        // MCP 必须显式授权服务与工具组合，普通工具允许列表不能隐式开放远程工具。
        if ((event.phase() == SecurityEvent.Phase.MCP_TOOL_INPUT
                        || event.phase() == SecurityEvent.Phase.MCP_TOOL_OUTPUT)
                && !allowedMcpTools.contains(event.operation())) {
            return Decision.deny("mcp-tool-not-allowed");
        }
        String permission = memoryPermissions.get(event.phase());
        if (permission != null) {
            if (event.context() == null) {
                return Decision.deny("missing-security-context");
            }
            if (!event.context().permissions().contains(permission)) {
                return Decision.deny("permission-denied");
            }
        }
        if (event.phase() == SecurityEvent.Phase.RETRIEVAL_INPUT
                && allowedRetrievers != null
                && !allowedRetrievers.contains(event.operation())) {
            return Decision.deny("retriever-not-allowed");
        }
        if (event.phase() == SecurityEvent.Phase.TOOL_INPUT
                && deniedTools.contains(event.operation())) {
            return Decision.deny("denied-tool");
        }
        if (event.phase() == SecurityEvent.Phase.TOOL_INPUT
                && allowedTools != null
                && !allowedTools.contains(event.operation())) {
            return Decision.deny("tool-not-allowed");
        }
        String text = event.text() == null ? "" : event.text();
        if (text.length() > maxChars) {
            return Decision.deny("text-limit");
        }
        String normalized = text.toLowerCase(Locale.ROOT);
        if (deniedText.stream().anyMatch(normalized::contains)) {
            return Decision.deny("denied-text");
        }
        return Decision.allow();
    }
}
