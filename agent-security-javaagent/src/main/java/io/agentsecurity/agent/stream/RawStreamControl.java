package io.agentsecurity.agent.stream;

import com.fasterxml.jackson.core.*;
import io.agentsecurity.agent.bridge.Bridge;
import io.agentsecurity.core.SecurityBlockedException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** 严格解析已支持的原始流控制事件，拒绝未知形状、重复字段及超限输入。 */
final class RawStreamControl {

    private static final JsonFactory JSON =
            JsonFactory.builder()
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .streamReadConstraints(
                            StreamReadConstraints.builder()
                                    .maxNestingDepth(8)
                                    .maxStringLength(100_000)
                                    .maxNumberLength(20)
                                    .build())
                    .build();

    private static final Set<String> FIELDS =
            Set.of(
                    "id",
                    "object",
                    "created",
                    "model",
                    "system_fingerprint",
                    "choices",
                    "usage",
                    "service_tier");

    public static String inspect(Object request, Object event, int remaining) {
        if (event == null
                || !event.getClass()
                        .getName()
                        .equals("dev.langchain4j.http.client.sse.ServerSentEvent")) {
            throw denied();
        }
        Object eventName = Bridge.call(event, "event");
        if (eventName != null && !eventName.equals("message")) {
            throw denied();
        }
        Object data = Bridge.call(event, "data");
        if (!(data instanceof String raw)) {
            throw denied();
        }
        if (raw.length() > remaining) {
            throw new SecurityBlockedException("stream-buffer-limit");
        }
        if (raw.equals("[DONE]")) {
            return raw;
        }
        try (JsonParser parser = JSON.createParser(raw)) {
            Object decoded = read(parser, parser.nextToken());
            if (parser.nextToken() != null
                    || !(decoded instanceof Map<?, ?> root)
                    || !FIELDS.containsAll(root.keySet())) {
                throw denied();
            }
            Object choices = root.get("choices");
            if (!(choices instanceof List<?> list)) {
                throw denied();
            }
            for (Object choice : list) {
                if (!(choice instanceof Map<?, ?> item)
                        || !Set.of("index", "delta", "finish_reason", "logprobs")
                                .containsAll(item.keySet())) {
                    throw denied();
                }
                if (!(item.get("index") instanceof Number)) {
                    throw denied();
                }
                Object reason = item.get("finish_reason");
                if (reason != null
                        && !Set.of("stop", "length", "tool_calls", "content_filter")
                                .contains(reason)) {
                    throw denied();
                }
                if (item.get("logprobs") != null) {
                    throw denied();
                }
                if (!(item.get("delta") instanceof Map<?, ?> delta)
                        || !Set.of("role", "content").containsAll(delta.keySet())) {
                    throw denied();
                }
                if (delta.get("role") != null && !delta.get("role").equals("assistant")) {
                    throw denied();
                }
                if (delta.get("content") != null && !delta.get("content").equals("")) {
                    throw denied();
                }
            }
            // Scan decoded strings, including metadata. JSON escapes cannot evade literal rules.
            inspectStrings(request, root);
            return raw;
        } catch (IOException | IllegalArgumentException error) {
            throw denied();
        }
    }

    private static Object read(JsonParser parser, JsonToken token) throws IOException {
        if (token == JsonToken.START_OBJECT) {
            Map<String, Object> result = new LinkedHashMap<>();
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                if (parser.currentToken() != JsonToken.FIELD_NAME) {
                    throw denied();
                }
                String name = parser.currentName();
                result.put(name, read(parser, parser.nextToken()));
            }
            return result;
        }
        if (token == JsonToken.START_ARRAY) {
            List<Object> result = new ArrayList<>();
            while (parser.nextToken() != JsonToken.END_ARRAY) {
                result.add(read(parser, parser.currentToken()));
            }
            return result;
        }
        if (token == JsonToken.VALUE_STRING) {
            return parser.getText();
        }
        if (token == JsonToken.VALUE_NUMBER_INT || token == JsonToken.VALUE_NUMBER_FLOAT) {
            return parser.getNumberValue();
        }
        if (token == JsonToken.VALUE_NULL) {
            return null;
        }
        throw denied();
    }

    private static void inspectStrings(Object request, Object node) {
        if (node instanceof String text) {
            Bridge.checkStreamText(request, text);
        } else if (node instanceof Map<?, ?> map) {
            map.forEach(
                    (key, value) -> {
                        Bridge.checkStreamText(request, key.toString());
                        inspectStrings(request, value);
                    });
        } else if (node instanceof List<?> list) {
            list.forEach(value -> inspectStrings(request, value));
        }
    }

    private static SecurityBlockedException denied() {
        return new SecurityBlockedException("unsupported-stream-event");
    }
}
