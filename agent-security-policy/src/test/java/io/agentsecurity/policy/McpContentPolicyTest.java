package io.agentsecurity.policy;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.*;
import io.agentsecurity.core.mcp.McpOperations;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class McpContentPolicyTest {
    @Test
    void resourceIdentifiersAreExactBoundedAndServerScoped() {
        String original = McpOperations.resource("inventory", "docs://items/one");
        assertEquals(original, McpOperations.resource("inventory", "docs://items/one"));
        assertTrue(original.length() <= 256);
        assertNotEquals(original, McpOperations.resource("other", "docs://items/one"));
        assertNotEquals(original, McpOperations.resource("inventory", "docs://items/%6fne"));
        assertThrows(
                IllegalArgumentException.class,
                () -> McpOperations.resource("inventory", "relative"));
        assertThrows(
                IllegalArgumentException.class,
                () -> McpOperations.resource("inventory", "docs://a/\ud800"));
        assertThrows(
                IllegalArgumentException.class,
                () -> McpOperations.resource("inventory", "docs:" + "x".repeat(1024)));
        assertThrows(
                IllegalArgumentException.class, () -> McpOperations.prompt("bad/server", "name"));
    }

    @Test
    void independentAllowListsApplyToInputAndOutput() {
        String resource = McpOperations.resource("inventory", "docs://items/one");
        String prompt = McpOperations.prompt("inventory", "summarize");
        var properties = new Properties();
        var empty = new LocalPolicy(properties);
        properties.setProperty("allow.mcp.resources", resource);
        properties.setProperty("allow.mcp.prompts", prompt);
        var policy = new LocalPolicy(properties);
        for (var phase :
                new SecurityEvent.Phase[] {
                    SecurityEvent.Phase.MCP_RESOURCE_INPUT,
                    SecurityEvent.Phase.MCP_RESOURCE_OUTPUT,
                    SecurityEvent.Phase.MCP_PROMPT_INPUT,
                    SecurityEvent.Phase.MCP_PROMPT_OUTPUT
                }) {
            String operation = phase.name().contains("RESOURCE") ? resource : prompt;
            assertFalse(empty.evaluate(new SecurityEvent(phase, operation, "safe")).allowed());
            assertTrue(policy.evaluate(new SecurityEvent(phase, operation, "safe")).allowed());
            assertFalse(
                    policy.evaluate(new SecurityEvent(phase, operation + "x", "safe")).allowed());
        }
        properties.setProperty("allow.mcp.resources", "*");
        assertThrows(IllegalArgumentException.class, () -> new LocalPolicy(properties));
    }
}
