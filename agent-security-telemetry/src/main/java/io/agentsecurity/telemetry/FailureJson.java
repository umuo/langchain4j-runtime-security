package io.agentsecurity.telemetry;

import com.fasterxml.jackson.core.JsonFactory;
import io.agentsecurity.core.diagnostics.FailureRecord;
import java.io.IOException;
import java.io.StringWriter;
import java.util.List;

/** 结构化故障 JSON v1；只序列化固定白名单字段，不反射展开异常或业务对象。 */
public final class FailureJson {
    private static final JsonFactory JSON = new JsonFactory();

    private FailureJson() {}

    public static String encode(List<FailureRecord> records) throws IOException {
        if (records.size() > 1024) {
            throw new IllegalArgumentException("Failure batch too large");
        }
        var output = new StringWriter();
        try (var json = JSON.createGenerator(output)) {
            json.writeStartObject();
            json.writeNumberField("schemaVersion", 1);
            json.writeArrayFieldStart("failures");
            for (var record : records) {
                json.writeStartObject();
                json.writeStringField("id", record.id().toString());
                json.writeStringField("timestamp", record.timestamp().toString());
                json.writeStringField("category", record.category().name());
                json.writeStringField("stage", record.stage().name());
                json.writeStringField("boundary", record.boundary().name());
                if (record.phase() != null) {
                    json.writeStringField("phase", record.phase().name());
                }
                if (record.eventId() != null) {
                    json.writeStringField("eventId", record.eventId().toString());
                }
                if (record.runId() != null) {
                    json.writeStringField("runId", record.runId().toString());
                }
                if (record.invocationId() != null) {
                    json.writeStringField("invocationId", record.invocationId().toString());
                }
                if (record.parentInvocationId() != null) {
                    json.writeStringField(
                            "parentInvocationId", record.parentInvocationId().toString());
                }
                json.writeNumberField("depth", record.depth());
                if (record.ruleFingerprint() != null) {
                    json.writeStringField("ruleFingerprint", record.ruleFingerprint());
                }
                if (record.policyFingerprint() != null) {
                    json.writeStringField("policyFingerprint", record.policyFingerprint());
                }
                json.writeEndObject();
            }
            json.writeEndArray();
            json.writeEndObject();
        }
        return output.toString();
    }
}
