package io.agentsecurity.policy.remote;

import com.fasterxml.jackson.core.*;
import io.agentsecurity.core.SecurityEvent;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Set;

/** 闭合、版本化的检测协议；拒绝重复字段、未知字段和尾随内容，不接受服务端任意规则文本。 */
final class RemoteProtocol {
    private static final JsonFactory JSON =
            JsonFactory.builder()
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .streamReadConstraints(
                            StreamReadConstraints.builder()
                                    .maxNestingDepth(4)
                                    .maxStringLength(256)
                                    .maxNumberLength(16)
                                    .build())
                    .build();

    private RemoteProtocol() {}

    static byte[] request(SecurityEvent event, String version, String content, int maximum)
            throws IOException {
        if (content == null || content.length() > maximum) {
            throw new IOException("Invalid request content");
        }
        var bytes = new ByteArrayOutputStream();
        // 在编码写入时限制 UTF-8 JSON 字节数，避免转义或多字节文本绕过请求上限。
        try (var json =
                JSON.createGenerator(
                        new OutputStream() {
                            @Override
                            public void write(int value) throws IOException {
                                if (bytes.size() >= maximum) {
                                    throw new IOException("Request too large");
                                }
                                bytes.write(value);
                            }

                            @Override
                            public void write(byte[] values, int offset, int length)
                                    throws IOException {
                                if (length > maximum - bytes.size()) {
                                    throw new IOException("Request too large");
                                }
                                bytes.write(values, offset, length);
                            }
                        })) {
            json.writeStartObject();
            json.writeNumberField("schemaVersion", 1);
            json.writeStringField("eventId", event.id().toString());
            json.writeStringField("phase", event.phase().name());
            json.writeStringField("policyVersion", version);
            json.writeStringField("content", content);
            json.writeEndObject();
        }
        return bytes.toByteArray();
    }

    static boolean allowed(byte[] body, SecurityEvent event, String version) throws IOException {
        var values = new HashMap<String, String>();
        String decoded =
                java.nio.charset.StandardCharsets.UTF_8
                        .newDecoder()
                        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                        .decode(java.nio.ByteBuffer.wrap(body))
                        .toString();
        try (var json = JSON.createParser(decoded)) {
            if (json.nextToken() != JsonToken.START_OBJECT) {
                throw new IOException("Invalid response");
            }
            while (json.nextToken() != JsonToken.END_OBJECT) {
                if (json.currentToken() != JsonToken.FIELD_NAME) {
                    throw new IOException("Invalid response");
                }
                String field = json.currentName();
                var token = json.nextToken();
                if (field.equals("schemaVersion")) {
                    if (token != JsonToken.VALUE_NUMBER_INT || !json.getText().equals("1")) {
                        throw new IOException("Invalid schema");
                    }
                } else if (!Set.of("eventId", "policyVersion", "decision").contains(field)
                        || token != JsonToken.VALUE_STRING) {
                    throw new IOException("Invalid response field");
                }
                values.put(field, json.getText());
            }
            if (json.nextToken() != null
                    || values.size() != 4
                    || !event.id().toString().equals(values.get("eventId"))
                    || !version.equals(values.get("policyVersion"))
                    || !Set.of("ALLOW", "DENY").contains(values.getOrDefault("decision", ""))) {
                throw new IOException("Uncorrelated or incomplete response");
            }
        }
        return values.get("decision").equals("ALLOW");
    }
}
