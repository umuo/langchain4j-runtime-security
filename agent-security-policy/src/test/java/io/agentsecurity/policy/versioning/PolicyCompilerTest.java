package io.agentsecurity.policy.versioning;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.SecurityEvent;
import io.agentsecurity.core.versioning.AtomicPolicy;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class PolicyCompilerTest {
    @Test
    void sourceMutationCannotChangeCompiledRulesAndKeyOrderDoesNotChangeDigest() {
        var source = new Properties();
        source.setProperty("deny.tools", "erase");
        source.setProperty("max.text.chars", "1000");
        var first = PolicyCompiler.compile("v1", source, null);
        var reordered = new Properties();
        reordered.setProperty("max.text.chars", "1000");
        reordered.setProperty("deny.tools", "erase");
        assertEquals(first.sha256(), PolicyCompiler.compile("v2", reordered, null).sha256());
        source.setProperty("deny.tools", "");
        assertFalse(
                first.detector()
                        .evaluate(new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "erase", ""))
                        .allowed());
    }

    @Test
    void invalidCandidateCannotReplaceActivePolicy() {
        var source = new Properties();
        var policies = new AtomicPolicy(PolicyCompiler.compile("v1", source, null), 4);
        source.setProperty("unknown", "private");
        assertThrows(
                IllegalArgumentException.class,
                () -> policies.publish(1, PolicyCompiler.compile("v2", source, null)));
        assertThrows(
                RuntimeException.class,
                () -> policies.publish(1, PolicyCompiler.compile("v2", new Properties(), "{}")));
        assertEquals(1, policies.state().generation());
        assertEquals("v1", policies.state().version());
    }

    @Test
    void bundleLimitsAndMalformedUnicodeAreRejected() {
        var source = new Properties();
        source.setProperty("deny.text", "x".repeat(8193));
        assertThrows(
                IllegalArgumentException.class, () -> PolicyCompiler.compile("v1", source, null));
        source.setProperty("deny.text", "\ud800");
        assertThrows(
                IllegalArgumentException.class, () -> PolicyCompiler.compile("v1", source, null));
    }
}
