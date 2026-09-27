package io.agentsecurity.policy;

import com.fasterxml.jackson.core.*;
import java.io.IOException;
import java.math.BigDecimal;
import java.util.*;

/** Bounded data-only parser. No polymorphic deserialization, coercion, references or external resources. */
final class StrictJson {
    private final JsonParser parser;
    private int remainingNodes = 20_000;
    private StrictJson(JsonParser parser) { this.parser = parser; }

    static Object parse(String input, int maxChars, int depth) {
        if (input == null || input.length() > maxChars) throw invalid();
        JsonFactory factory = JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(depth).maxNameLength(1024)
                        .maxStringLength(maxChars).maxNumberLength(128).build()).build();
        try (JsonParser parser = factory.createParser(input)) {
            Object value = new StrictJson(parser).read(parser.nextToken());
            if (parser.nextToken() != null) throw invalid();
            return value;
        } catch (IOException | ArithmeticException error) { throw invalid(); }
    }

    private Object read(JsonToken token) throws IOException {
        if (--remainingNodes < 0) throw invalid();
        if (token == JsonToken.START_OBJECT) {
            Map<String, Object> value = new LinkedHashMap<>();
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                if (parser.currentToken() != JsonToken.FIELD_NAME) throw invalid();
                String name = unicode(parser.currentName());
                value.put(name, read(parser.nextToken()));
            }
            return value;
        }
        if (token == JsonToken.START_ARRAY) {
            List<Object> value = new ArrayList<>();
            while (parser.nextToken() != JsonToken.END_ARRAY) value.add(read(parser.currentToken()));
            return value;
        }
        if (token == JsonToken.VALUE_STRING) return unicode(parser.getText());
        if (token == JsonToken.VALUE_TRUE) return Boolean.TRUE;
        if (token == JsonToken.VALUE_FALSE) return Boolean.FALSE;
        if (token == JsonToken.VALUE_NULL) return null;
        if (token == JsonToken.VALUE_NUMBER_INT || token == JsonToken.VALUE_NUMBER_FLOAT) {
            BigDecimal number = parser.getDecimalValue();
            if (number.precision() > 128 || Math.abs((long) number.scale()) > 1024) throw invalid();
            return number;
        }
        throw invalid();
    }

    private static String unicode(String text) {
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (++index == text.length() || !Character.isLowSurrogate(text.charAt(index))) throw invalid();
            } else if (Character.isLowSurrogate(character)) throw invalid();
        }
        return text;
    }

    static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid or unsupported JSON policy/data"); }
}
