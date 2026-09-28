package io.agentsecurity.policy;

import io.agentsecurity.core.Decision;
import io.agentsecurity.core.Detector;
import io.agentsecurity.core.LocalPolicy;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityEvent;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** 编译并执行闭合的工具参数规则，支持精确类型、权限及可信身份参数绑定，不提供完整 JSON Schema。 */
public final class ToolPolicy implements Detector {

    private static final int MAX_POLICY_BYTES = 1_048_576;

    private final Map<String, Rule> tools;

    private final int maxArgumentChars;

    private final LocalPolicy decodedTextPolicy;

    private final Map<String, Set<String>> permissions;

    private final Set<String> contextualTools;

    private ToolPolicy(
            Map<String, Rule> tools,
            int maxArgumentChars,
            LocalPolicy decodedTextPolicy,
            Map<String, Set<String>> permissions,
            Set<String> contextualTools) {
        this.tools = Map.copyOf(tools);
        this.maxArgumentChars = maxArgumentChars;
        this.decodedTextPolicy = decodedTextPolicy;
        this.permissions = Map.copyOf(permissions);
        this.contextualTools = Set.copyOf(contextualTools);
    }

    public static ToolPolicy fromJson(String json) {
        return fromJson(json, null);
    }

    /**
     * Optionally apply the same local text rules to decoded keys/string values, so JSON escapes do
     * not hide them.
     */
    public static ToolPolicy fromJson(String json, LocalPolicy decodedTextPolicy) {
        Map<String, Object> root = object(StrictJson.parse(json, MAX_POLICY_BYTES, 64));
        keys(root, Set.of("schemaVersion", "maxArgumentChars", "tools", "permissions"));
        if (integer(root.get("schemaVersion")) != 1) {
            throw StrictJson.invalid();
        }
        int maxChars = bounded(root, "maxArgumentChars", 100_000, 1, 1_000_000);
        Map<String, Rule> rules = new LinkedHashMap<>();
        Set<String> contextual = new HashSet<>();
        Map<String, Object> definitions = object(root.get("tools"));
        if (definitions.size() > 1024) {
            throw StrictJson.invalid();
        }
        for (var entry : definitions.entrySet()) {
            if (!entry.getKey().matches("[\\p{L}\\p{N}_.-]{1,128}")
                    && !entry.getKey().matches("mcp:[a-zA-Z0-9_.-]{1,100}/[a-zA-Z0-9_.-]{1,100}")) {
                throw StrictJson.invalid();
            }
            Rule rule = compile(object(entry.getValue()), 0);
            if (!(rule instanceof ObjectRule)) {
                throw StrictJson.invalid();
            }
            rules.put(entry.getKey(), rule);
            if (usesContext(entry.getValue())) {
                contextual.add(entry.getKey());
            }
        }
        Map<String, Set<String>> permissions = new HashMap<>();
        if (root.containsKey("permissions")) {
            for (var entry : object(root.get("permissions")).entrySet()) {
                if (!rules.containsKey(entry.getKey())) {
                    throw StrictJson.invalid();
                }
                Set<String> values = new HashSet<>();
                for (Object value : array(entry.getValue())) {
                    if (!(value instanceof String permission)
                            || !permission.matches("[a-zA-Z0-9@._:-]{1,128}")
                            || !values.add(permission)) {
                        throw StrictJson.invalid();
                    }
                }
                if (values.isEmpty() || values.size() > 128) {
                    throw StrictJson.invalid();
                }
                permissions.put(entry.getKey(), Set.copyOf(values));
                contextual.add(entry.getKey());
            }
        }
        return new ToolPolicy(rules, maxChars, decodedTextPolicy, permissions, contextual);
    }

    public static ToolPolicy fromPath(Path path) throws IOException {
        return fromPath(path, null);
    }

    public static ToolPolicy fromPath(Path path, LocalPolicy decodedTextPolicy) throws IOException {
        byte[] bytes;
        try (var input = Files.newInputStream(path)) {
            bytes = input.readNBytes(MAX_POLICY_BYTES + 1);
        }
        if (bytes.length > MAX_POLICY_BYTES) {
            throw StrictJson.invalid();
        }
        try {
            String text =
                    StandardCharsets.UTF_8
                            .newDecoder()
                            .onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT)
                            .decode(ByteBuffer.wrap(bytes))
                            .toString();
            return fromJson(text, decodedTextPolicy);
        } catch (CharacterCodingException error) {
            throw StrictJson.invalid();
        }
    }

    @Override
    public Decision evaluate(SecurityEvent event) {
        if (event.phase() != SecurityEvent.Phase.TOOL_INPUT
                && event.phase() != SecurityEvent.Phase.MCP_TOOL_INPUT) {
            return Decision.allow();
        }
        Rule rule = tools.get(event.operation());
        if (rule == null) {
            return Decision.deny("tool-not-allowed");
        }
        if (contextualTools.contains(event.operation()) && event.context() == null) {
            return Decision.deny("missing-security-context");
        }
        Set<String> required = permissions.get(event.operation());
        if (required != null && !event.context().permissions().containsAll(required)) {
            return Decision.deny("permission-denied");
        }
        String arguments = event.text();
        if (arguments != null && arguments.length() > maxArgumentChars) {
            return Decision.deny("tool-arguments-limit");
        }
        // LangChain4j may represent a no-argument tool invocation with null/empty arguments.
        if (arguments == null || arguments.isBlank()) {
            arguments = "{}";
        }
        Object decoded;
        try {
            decoded = StrictJson.parse(arguments, maxArgumentChars, 16);
        } catch (IllegalArgumentException error) {
            return Decision.deny("invalid-tool-arguments");
        }
        if (!rule.accepts(decoded, event.context())) {
            return Decision.deny("tool-argument-policy");
        }
        if (decodedTextPolicy != null) {
            StringBuilder text = new StringBuilder();
            strings(decoded, text);
            return decodedTextPolicy.evaluate(
                    new SecurityEvent(
                            event.id(),
                            event.phase(),
                            event.operation(),
                            text.toString(),
                            event.context()));
        }
        return Decision.allow();
    }

    private static void strings(Object value, StringBuilder output) {
        if (value instanceof String text) {
            output.append(text).append('\n');
        } else if (value instanceof Map<?, ?> map) {
            map.forEach(
                    (key, item) -> {
                        output.append(key).append('\n');
                        strings(item, output);
                    });
        } else if (value instanceof List<?> list) {
            list.forEach(item -> strings(item, output));
        }
    }

    private static boolean usesContext(Object value) {
        if (value instanceof Map<?, ?> map) {
            if (map.get("equalsContext") instanceof String) {
                return true;
            }
            return map.values().stream().anyMatch(ToolPolicy::usesContext);
        }
        return value instanceof List<?> list && list.stream().anyMatch(ToolPolicy::usesContext);
    }

    private interface Rule {

        boolean accepts(Object value, SecurityContext context);
    }

    private record ObjectRule(Map<String, Rule> properties, Set<String> required) implements Rule {

        @Override
        public boolean accepts(Object value, SecurityContext context) {
            if (!(value instanceof Map<?, ?> map)
                    || !map.keySet().containsAll(required)
                    || !properties.keySet().containsAll(map.keySet())) {
                return false;
            }
            for (var item : map.entrySet()) {
                if (!properties.get(item.getKey()).accepts(item.getValue(), context)) {
                    return false;
                }
            }
            return true;
        }
    }

    private static Rule compile(Map<String, Object> schema, int depth) {
        if (depth > 12 || !(schema.get("type") instanceof String type)) {
            throw StrictJson.invalid();
        }
        return switch (type) {
            case "object" -> {
                keys(schema, Set.of("type", "properties", "required", "additionalProperties"));
                if (schema.containsKey("additionalProperties")
                        && !Boolean.FALSE.equals(schema.get("additionalProperties"))) {
                    throw StrictJson.invalid();
                }
                Map<String, Rule> properties = new LinkedHashMap<>();
                for (var entry : object(schema.get("properties")).entrySet()) {
                    if (entry.getKey().isEmpty()) {
                        throw StrictJson.invalid();
                    }
                    properties.put(entry.getKey(), compile(object(entry.getValue()), depth + 1));
                }
                Set<String> required = new HashSet<>();
                if (schema.containsKey("required")) {
                    for (Object field : array(schema.get("required"))) {
                        if (!(field instanceof String name)
                                || !properties.containsKey(name)
                                || !required.add(name)) {
                            throw StrictJson.invalid();
                        }
                    }
                }
                yield new ObjectRule(Map.copyOf(properties), Set.copyOf(required));
            }
            case "array" -> {
                keys(schema, Set.of("type", "items", "minItems", "maxItems"));
                int max = bounded(schema, "maxItems", 64, 0, 4096);
                int min = bounded(schema, "minItems", 0, 0, max);
                Rule items = compile(object(schema.get("items")), depth + 1);
                yield (value, context) ->
                        value instanceof List<?> list
                                && list.size() >= min
                                && list.size() <= max
                                && list.stream().allMatch(item -> items.accepts(item, context));
            }
            case "string" -> {
                keys(schema, Set.of("type", "enum", "minLength", "maxLength", "equalsContext"));
                int max = bounded(schema, "maxLength", 256, 0, 1_000_000);
                int min = bounded(schema, "minLength", 0, 0, max);
                Rule bounds =
                        (value, context) ->
                                value instanceof String text
                                        && text.codePointCount(0, text.length()) >= min
                                        && text.codePointCount(0, text.length()) <= max;
                Rule scalar = withEnum(schema, bounds);
                if (!schema.containsKey("equalsContext")) {
                    yield scalar;
                }
                Object binding = schema.get("equalsContext");
                if (!(binding instanceof String)
                        || !Set.of("tenantId", "principalId").contains(binding)) {
                    throw StrictJson.invalid();
                }
                yield (value, context) ->
                        scalar.accepts(value, context)
                                && context != null
                                && value.equals(
                                        binding.equals("tenantId")
                                                ? context.tenantId()
                                                : context.principalId());
            }
            case "integer", "number" -> {
                keys(schema, Set.of("type", "enum", "minimum", "maximum"));
                BigDecimal min =
                        schema.containsKey("minimum") ? number(schema.get("minimum")) : null;
                BigDecimal max =
                        schema.containsKey("maximum") ? number(schema.get("maximum")) : null;
                if (min != null && max != null && min.compareTo(max) > 0) {
                    throw StrictJson.invalid();
                }
                Rule bounds =
                        (value, context) ->
                                value instanceof BigDecimal numeric
                                        && (!type.equals("integer")
                                                || numeric.stripTrailingZeros().scale() <= 0)
                                        && (min == null || numeric.compareTo(min) >= 0)
                                        && (max == null || numeric.compareTo(max) <= 0);
                yield withEnum(schema, bounds);
            }
            case "boolean" -> {
                keys(schema, Set.of("type", "enum"));
                yield withEnum(schema, (value, context) -> value instanceof Boolean);
            }
            default -> throw StrictJson.invalid();
        };
    }

    private static Rule withEnum(Map<String, Object> schema, Rule bounds) {
        if (!schema.containsKey("enum")) {
            return bounds;
        }
        List<Object> values = array(schema.get("enum"));
        if (values.isEmpty()
                || values.size() > 1024
                || !values.stream().allMatch(value -> bounds.accepts(value, null))) {
            throw StrictJson.invalid();
        }
        List<Object> allowed = List.copyOf(values);
        return (value, context) ->
                bounds.accepts(value, context)
                        && allowed.stream()
                                .anyMatch(
                                        item ->
                                                item instanceof BigDecimal a
                                                                && value instanceof BigDecimal b
                                                        ? a.compareTo(b) == 0
                                                        : item.equals(value));
    }

    private static void keys(Map<String, Object> object, Set<String> supported) {
        if (!supported.containsAll(object.keySet())) {
            throw StrictJson.invalid();
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        if (!(value instanceof Map<?, ?> map)) {
            throw StrictJson.invalid();
        }
        return (Map<String, Object>) map;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> array(Object value) {
        if (!(value instanceof List<?> list)) {
            throw StrictJson.invalid();
        }
        return (List<Object>) list;
    }

    private static BigDecimal number(Object value) {
        if (value instanceof BigDecimal number) {
            return number;
        }
        throw StrictJson.invalid();
    }

    private static int integer(Object value) {
        try {
            return number(value).intValueExact();
        } catch (ArithmeticException error) {
            throw StrictJson.invalid();
        }
    }

    private static int bounded(
            Map<String, Object> map, String name, int fallback, int min, int max) {
        int value = map.containsKey(name) ? integer(map.get(name)) : fallback;
        if (value < min || value > max) {
            throw StrictJson.invalid();
        }
        return value;
    }
}
