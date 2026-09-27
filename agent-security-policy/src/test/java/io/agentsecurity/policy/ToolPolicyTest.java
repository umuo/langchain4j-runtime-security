package io.agentsecurity.policy;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.Decision;
import io.agentsecurity.core.LocalPolicy;
import io.agentsecurity.core.PolicyEngine;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityEvent;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ToolPolicyTest {

    @TempDir Path directory;

    static final String POLICY =
            """
        {"schemaVersion":1,"tools":{
          "lookup":{"type":"object","required":["customerId","limit"],"properties":{
            "customerId":{"type":"string","enum":["customer-1","customer-2"]},
            "limit":{"type":"integer","minimum":1,"maximum":10},
            "note":{"type":"string","maxLength":32},
            "options":{"type":"object","properties":{"active":{"type":"boolean","enum":[true]}}},
            "tags":{"type":"array","minItems":1,"maxItems":2,"items":{"type":"string","enum":["one","two"]}},
            "amount":{"type":"number","minimum":0.01,"maximum":1.25,"enum":[0.1,1.25]}
          }},
          "ping":{"type":"object","properties":{}}
        }}
        """;

    static final ToolPolicy policy = ToolPolicy.fromJson(POLICY);

    static Decision check(ToolPolicy policy, String name, String arguments) {
        return policy.evaluate(new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, name, arguments));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{\"customerId\":\"customer-1\",\"limit\":1}",
                "{\"customerId\":\"customer-2\",\"limit\":10.0,\"options\":{\"active\":true},\"tags\":[\"one\",\"two\"],\"amount\":0.10}",
                "{\"customerId\":\"customer-1\",\"limit\":1e1,\"amount\":1.25}",
                "{\"customer\\u0049d\":\"customer-\\u0031\",\"limit\":3}"
            })
    void validTypedArgumentsAndDecodedNamesPass(String arguments) {
        assertTrue(check(policy, "lookup", arguments).allowed());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{}",
                "null",
                "[]",
                "{\"customerId\":\"customer-1\"}",
                "{\"customerId\":\"customer-3\",\"limit\":1}",
                "{\"customerId\":\"customer-\\u0033\",\"limit\":1}",
                "{\"CustomerId\":\"customer-1\",\"limit\":1}",
                "{\"customerId\":null,\"limit\":1}",
                "{\"customerId\":\"customer-1\",\"limit\":\"1\"}",
                "{\"customerId\":\"customer-1\",\"limit\":true}",
                "{\"customerId\":\"customer-1\",\"limit\":1.1}",
                "{\"customerId\":\"customer-1\",\"limit\":0}",
                "{\"customerId\":\"customer-1\",\"limit\":11}",
                "{\"customerId\":\"customer-1\",\"limit\":1,\"admin\":true}",
                "{\"customerId\":\"customer-1\",\"limit\":1,\"options\":{\"unknown\":true}}",
                "{\"customerId\":\"customer-1\",\"limit\":1,\"options\":{\"active\":false}}",
                "{\"customerId\":\"customer-1\",\"limit\":1,\"tags\":[]}",
                "{\"customerId\":\"customer-1\",\"limit\":1,\"tags\":[\"one\",\"one\",\"one\"]}",
                "{\"customerId\":\"customer-1\",\"limit\":1,\"amount\":0.5}"
            })
    void schemaRejectsUnknownFieldsCoercionAndUnauthorizedValues(String arguments) {
        assertEquals("tool-argument-policy", check(policy, "lookup", arguments).ruleId());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{",
                "{} {}",
                "{\"limit\":1,\"limit\":2}",
                "{\"limit\":1,\"l\\u0069mit\":2}",
                "{\"limit\":NaN}",
                "{\"limit\":Infinity}",
                "{\"limit\":01}",
                "{\"limit\":1e100000000}",
                "{\"limit\":1,}",
                "{\"note\":\"\\uD800\"}",
                "{/* comment */}",
                "{unquoted:1}"
            })
    void ambiguousOrNonstandardJsonIsRejectedWithoutParserDetails(String arguments) {
        var decision = check(policy, "lookup", arguments);
        assertEquals("invalid-tool-arguments", decision.ruleId());
        assertFalse(decision.toString().contains(arguments));
    }

    @Test
    void toolsAreClosedAndNoArgumentRepresentationsAreEquivalent() {
        assertEquals("tool-not-allowed", check(policy, "other", "{}").ruleId());
        for (String empty : new String[] {null, "", " ", "{}"}) {
            assertTrue(check(policy, "ping", empty).allowed());
        }
        assertEquals(
                "tool-not-allowed",
                check(ToolPolicy.fromJson("{\"schemaVersion\":1,\"tools\":{}}"), "ping", "{}")
                        .ruleId());
        assertTrue(
                policy.evaluate(
                                new SecurityEvent(
                                        SecurityEvent.Phase.MODEL_INPUT, "chat", "not-json"))
                        .allowed());
    }

    @Test
    void decodedContentRulesCannotBeBypassedWithUnicodeEscapes() {
        Properties props = new Properties();
        props.setProperty("deny.text", "secret");
        var guarded = ToolPolicy.fromJson(POLICY, new LocalPolicy(props));
        assertEquals(
                "denied-text",
                check(
                                guarded,
                                "lookup",
                                "{\"customerId\":\"customer-1\",\"limit\":1,\"note\":\"s\\u0065cret\"}")
                        .ruleId());
    }

    @Test
    void unicodeLengthUsesCodePointsAndRejectsOverLimit() {
        var unicode =
                ToolPolicy.fromJson(
                        """
            {"schemaVersion":1,"tools":{"t":{"type":"object","properties":{"s":{"type":"string","maxLength":1}}}}}
            """);
        assertTrue(check(unicode, "t", "{\"s\":\"\\uD83D\\uDE00\"}").allowed());
        assertEquals("tool-argument-policy", check(unicode, "t", "{\"s\":\"ab\"}").ruleId());
    }

    @Test
    void argumentLengthDepthAndNodeCountsAreBounded() {
        var tiny =
                ToolPolicy.fromJson(
                        "{\"schemaVersion\":1,\"maxArgumentChars\":8,\"tools\":{\"t\":{\"type\":\"object\",\"properties\":{}}}}");
        assertEquals("tool-arguments-limit", check(tiny, "t", " ".repeat(9)).ruleId());
        assertEquals(
                "invalid-tool-arguments",
                check(policy, "lookup", "[".repeat(20) + "0" + "]".repeat(20)).ruleId());
        assertEquals(
                "invalid-tool-arguments",
                check(policy, "lookup", "[" + "0,".repeat(20001) + "0]").ruleId());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{\"schemaVersion\":2,\"tools\":{}}",
                "{\"schemaVersion\":1,\"tools\":{},\"typo\":true}",
                "{\"schemaVersion\":1,\"schemaVersion\":1,\"tools\":{}}",
                "{\"schemaVersion\":1}",
                "{\"schemaVersion\":1,\"tools\":{\"*\":{\"type\":\"object\",\"properties\":{}}}}"
            })
    void invalidPolicyRootsFailAtStartup(String json) {
        assertThrows(IllegalArgumentException.class, () -> ToolPolicy.fromJson(json));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "{\"type\":\"string\"}",
                "{\"type\":\"object\",\"properties\":{},\"additionalProperties\":true}",
                "{\"type\":\"object\",\"properties\":{},\"required\":[\"missing\"]}",
                "{\"type\":\"object\",\"properties\":{\"s\":{\"type\":\"string\",\"format\":\"uri\"}}}",
                "{\"type\":\"object\",\"properties\":{\"s\":{\"type\":\"string\",\"enum\":[]}}}",
                "{\"type\":\"object\",\"properties\":{\"s\":{\"type\":\"string\",\"enum\":[1]}}}",
                "{\"type\":\"object\",\"properties\":{\"n\":{\"type\":\"integer\",\"minimum\":5,\"maximum\":1}}}",
                "{\"type\":\"object\",\"properties\":{\"x\":{\"$ref\":\"https://example.com/schema\"}}}"
            })
    void unsupportedRulesAreRejectedInsteadOfIgnored(String schema) {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ToolPolicy.fromJson(
                                "{\"schemaVersion\":1,\"tools\":{\"t\":" + schema + "}}"));
    }

    @Test
    void loadingIsBoundedAndRejectsMalformedUtf8WithoutEchoingSecrets() throws Exception {
        Path file = directory.resolve("rules.json");
        Files.write(file, new byte[] {(byte) 0xc3, (byte) 0x28});
        var encoding =
                assertThrows(IllegalArgumentException.class, () -> ToolPolicy.fromPath(file, null));
        assertNull(encoding.getCause());
        Files.writeString(file, " ".repeat(1_048_577));
        assertThrows(IllegalArgumentException.class, () -> ToolPolicy.fromPath(file, null));
        Files.writeString(file, POLICY);
        assertTrue(check(ToolPolicy.fromPath(file, null), "ping", "{}").allowed());
    }

    @Test
    void policyIsSafeForConcurrentChecksAndAuditsStableReasons() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> work = new ArrayList<>();
            for (int i = 0; i < 100; i++) {
                work.add(
                        executor.submit(
                                () -> {
                                    assertTrue(
                                            check(
                                                            policy,
                                                            "lookup",
                                                            "{\"customerId\":\"customer-1\",\"limit\":5}")
                                                    .allowed());
                                    assertEquals(
                                            "tool-argument-policy",
                                            check(
                                                            policy,
                                                            "lookup",
                                                            "{\"customerId\":\"private-value\",\"limit\":5}")
                                                    .ruleId());
                                }));
            }
            for (var task : work) {
                task.get(2, TimeUnit.SECONDS);
            }
        } finally {
            executor.shutdownNow();
        }
        List<Decision> audits = new ArrayList<>();
        try (var engine =
                new PolicyEngine(List.of(policy), (event, decision) -> audits.add(decision))) {
            assertEquals(
                    "tool-not-allowed",
                    assertThrows(
                                    SecurityBlockedException.class,
                                    () ->
                                            engine.check(
                                                    new SecurityEvent(
                                                            SecurityEvent.Phase.TOOL_INPUT,
                                                            "missing",
                                                            "private")))
                            .ruleId());
            assertEquals(List.of(Decision.deny("tool-not-allowed")), audits);
        }
    }
}
