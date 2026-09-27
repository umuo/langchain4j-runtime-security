package io.agentsecurity.telemetry;

import com.fasterxml.jackson.core.*;
import io.agentsecurity.core.telemetry.TelemetryRecord;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

/** OTLP/HTTP JSON 日志编解码；关联 UUID 是属性，不伪造 span 或 trace ID。 */
final class OtlpJson {
    private static final JsonFactory JSON =
            JsonFactory.builder()
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .streamReadConstraints(
                            StreamReadConstraints.builder()
                                    .maxNestingDepth(16)
                                    .maxStringLength(16384)
                                    .build())
                    .build();

    private OtlpJson() {}

    static byte[] encode(String service, List<TelemetryRecord> records) throws IOException {
        var bytes = new ByteArrayOutputStream();
        try (var json = JSON.createGenerator(bytes)) {
            json.writeStartObject();
            json.writeArrayFieldStart("resourceLogs");
            json.writeStartObject();
            json.writeObjectFieldStart("resource");
            json.writeArrayFieldStart("attributes");
            attribute(json, "service.name", service);
            json.writeEndArray();
            json.writeEndObject();
            json.writeArrayFieldStart("scopeLogs");
            json.writeStartObject();
            json.writeObjectFieldStart("scope");
            json.writeStringField("name", "io.agentsecurity");
            json.writeEndObject();
            json.writeArrayFieldStart("logRecords");
            for (var record : records) {
                json.writeStartObject();
                json.writeStringField(
                        "timeUnixNano",
                        Long.toString(
                                Math.addExact(
                                        Math.multiplyExact(
                                                record.timestamp().getEpochSecond(), 1000000000L),
                                        record.timestamp().getNano())));
                json.writeObjectFieldStart("body");
                json.writeStringField("stringValue", "agent-security-event");
                json.writeEndObject();
                json.writeArrayFieldStart("attributes");
                attribute(json, "security.event.id", record.eventId());
                attribute(json, "security.phase", record.phase());
                attribute(json, "security.outcome", record.outcome());
                attribute(json, "security.run.id", record.runId());
                attribute(json, "security.invocation.id", record.invocationId());
                attribute(json, "security.parent.invocation.id", record.parentInvocationId());
                json.writeStartObject();
                json.writeStringField("key", "security.duration.nanos");
                json.writeObjectFieldStart("value");
                json.writeStringField("intValue", Long.toString(record.durationNanos()));
                json.writeEndObject();
                json.writeEndObject();
                json.writeEndArray();
                json.writeEndObject();
            }
            json.writeEndArray();
            json.writeEndObject();
            json.writeEndArray();
            json.writeEndObject();
            json.writeEndArray();
            json.writeEndObject();
        }
        return bytes.toByteArray();
    }

    private static void attribute(JsonGenerator json, String name, Object value)
            throws IOException {
        if (value == null) {
            return;
        }
        json.writeStartObject();
        json.writeStringField("key", name);
        json.writeObjectFieldStart("value");
        json.writeStringField("stringValue", value.toString());
        json.writeEndObject();
        json.writeEndObject();
    }

    /** 返回拒收条数；部分成功（包括仅告警）均不重试；未知字段按 OTLP JSON 约定忽略。 */
    static int rejected(byte[] body, int batchSize) throws IOException {
        int rejected = 0;
        try (var json = JSON.createParser(body)) {
            if (json.nextToken() != JsonToken.START_OBJECT) {
                throw new IOException("Invalid response");
            }
            while (json.nextToken() != JsonToken.END_OBJECT) {
                if (json.currentToken() != JsonToken.FIELD_NAME) {
                    throw new IOException("Invalid response");
                }
                String key = json.currentName();
                var token = json.nextToken();
                if (key.equals("partialSuccess")) {
                    if (token != JsonToken.START_OBJECT) {
                        throw new IOException("Invalid partial response");
                    }
                    while (json.nextToken() != JsonToken.END_OBJECT) {
                        if (json.currentToken() != JsonToken.FIELD_NAME) {
                            throw new IOException("Invalid response");
                        }
                        String field = json.currentName();
                        token = json.nextToken();
                        if (field.equals("rejectedLogRecords")) {
                            if (token != JsonToken.VALUE_STRING
                                    && token != JsonToken.VALUE_NUMBER_INT) {
                                throw new IOException("Invalid rejected count");
                            }
                            try {
                                rejected = Integer.parseInt(json.getText());
                            } catch (NumberFormatException invalid) {
                                throw new IOException("Invalid rejected count");
                            }
                            if (rejected < 0 || rejected > batchSize) {
                                throw new IOException("Invalid rejected count");
                            }
                        } else {
                            json.skipChildren();
                        }
                    }
                } else {
                    json.skipChildren();
                }
            }
            if (json.nextToken() != null) {
                throw new IOException("Trailing response");
            }
        }
        return rejected;
    }
}
