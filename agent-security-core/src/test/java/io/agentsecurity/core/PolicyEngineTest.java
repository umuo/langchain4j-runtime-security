package io.agentsecurity.core;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class PolicyEngineTest {

    private final SecurityEvent event =
            new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "sendEmail", "private-payload");

    @Test
    void denialShortCircuitsDetectorsAndAudits() {
        AtomicInteger audit = new AtomicInteger();
        var engine =
                new PolicyEngine(
                        List.of(
                                e -> Decision.deny("test"),
                                e -> {
                                    fail("Must short circuit");
                                    return null;
                                }),
                        (e, d) -> {
                            assertFalse(d.allowed());
                            audit.incrementAndGet();
                        });
        assertThrows(SecurityBlockedException.class, () -> engine.check(event));
        assertEquals(1, audit.get());
    }

    @Test
    void detectorExceptionAndNullFailClosed() {
        for (Detector detector :
                List.<Detector>of(
                        e -> {
                            throw new IllegalStateException();
                        },
                        e -> null)) {
            var engine = new PolicyEngine(List.of(detector), (e, d) -> {});
            assertEquals(
                    "detector-error",
                    assertThrows(SecurityBlockedException.class, () -> engine.check(event))
                            .ruleId());
        }
    }

    @Test
    void auditFailureFailsClosed() {
        var engine =
                new PolicyEngine(
                        List.of(),
                        (e, d) -> {
                            throw new IllegalStateException();
                        });
        assertEquals(
                "audit-error",
                assertThrows(SecurityBlockedException.class, () -> engine.check(event)).ruleId());
    }

    @Test
    void configRejectsTyposAndInvalidLimits() {
        Properties p = new Properties();
        p.setProperty("deny.tool", "x");
        assertThrows(IllegalArgumentException.class, () -> new LocalPolicy(p));
        p.clear();
        p.setProperty("max.text.chars", "0");
        assertThrows(IllegalArgumentException.class, () -> new LocalPolicy(p));
    }

    @Test
    void omittedOrBlankTextLimitAllowsLongTextButKeepsContentRules() {
        for (String configured : new String[] {null, "", "  "}) {
            Properties properties = new Properties();
            if (configured != null) {
                properties.setProperty("max.text.chars", configured);
            }
            properties.setProperty("deny.text", "SECRET");
            LocalPolicy policy = new LocalPolicy(properties);
            assertEquals(0, policy.maxTextChars());
            String longText = "x".repeat(100001);
            assertTrue(
                    policy.evaluate(
                                    new SecurityEvent(
                                            SecurityEvent.Phase.MODEL_INPUT, "chat", longText))
                            .allowed());
            assertFalse(
                    policy.evaluate(
                                    new SecurityEvent(
                                            SecurityEvent.Phase.MODEL_INPUT,
                                            "chat",
                                            longText + "SECRET"))
                            .allowed());
        }
    }

    @Test
    void literalRulesAndLengthLimit() {
        Properties p = new Properties();
        p.setProperty("deny.tools", "sendEmail");
        p.setProperty("deny.text", "SECRET");
        p.setProperty("max.text.chars", "20");
        LocalPolicy policy = new LocalPolicy(p);
        assertFalse(policy.evaluate(event).allowed());
        assertFalse(
                policy.evaluate(
                                new SecurityEvent(
                                        SecurityEvent.Phase.MODEL_INPUT, "chat", "a secret"))
                        .allowed());
        assertFalse(
                policy.evaluate(
                                new SecurityEvent(
                                        SecurityEvent.Phase.MODEL_INPUT, "chat", "x".repeat(21)))
                        .allowed());
        assertTrue(
                policy.evaluate(new SecurityEvent(SecurityEvent.Phase.MODEL_INPUT, "chat", "hello"))
                        .allowed());
    }

    @Test
    void explicitAllowlistIsClosedAndDenyRulesTakePriority() {
        Properties properties = new Properties();
        properties.setProperty("allow.tools", "read,sendEmail");
        properties.setProperty("deny.tools", "sendEmail");
        var policy = new LocalPolicy(properties);
        assertTrue(
                policy.evaluate(new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "read", "{}"))
                        .allowed());
        assertEquals("denied-tool", policy.evaluate(event).ruleId());
        assertEquals(
                "tool-not-allowed",
                policy.evaluate(new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "other", "{}"))
                        .ruleId());
        properties.setProperty("allow.tools", "");
        assertEquals(
                "tool-not-allowed",
                new LocalPolicy(properties)
                        .evaluate(new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "read", "{}"))
                        .ruleId());
    }
}
