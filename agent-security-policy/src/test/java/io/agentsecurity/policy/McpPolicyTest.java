package io.agentsecurity.policy;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.*;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class McpPolicyTest {
    @Test
    void explicitServerToolPairIsRequiredForBothPhases() {
        var properties = new Properties();
        properties.setProperty("allow.tools", "lookup");
        var empty = new LocalPolicy(properties);
        properties.setProperty("allow.mcp.tools", "mcp:inventory/lookup");
        var policy = new LocalPolicy(properties);
        for (var phase :
                new SecurityEvent.Phase[] {
                    SecurityEvent.Phase.MCP_TOOL_INPUT, SecurityEvent.Phase.MCP_TOOL_OUTPUT
                }) {
            assertFalse(
                    empty.evaluate(new SecurityEvent(phase, "mcp:inventory/lookup", "{}"))
                            .allowed());
            assertTrue(
                    policy.evaluate(new SecurityEvent(phase, "mcp:inventory/lookup", "{}"))
                            .allowed());
            assertFalse(
                    policy.evaluate(new SecurityEvent(phase, "mcp:other/lookup", "{}")).allowed());
        }
        properties.setProperty("allow.mcp.tools", "mcp:*/lookup");
        assertThrows(IllegalArgumentException.class, () -> new LocalPolicy(properties));
    }

    @Test
    void structuredMcpArgumentsUseExistingClosedSchemaAndDecodedChecks() {
        var properties = new Properties();
        properties.setProperty("allow.mcp.tools", "mcp:inventory/lookup");
        properties.setProperty("deny.text", "secret");
        var policy =
                ToolPolicy.fromJson(
                        """
                {"schemaVersion":1,"tools":{"mcp:inventory/lookup":{
                "type":"object","required":["q"],"properties":{"q":{"type":"string"}}}}}
                """,
                        new LocalPolicy(properties));
        assertTrue(policy.evaluate(event("mcp:inventory/lookup", "{\"q\":\"safe\"}")).allowed());
        assertEquals(
                "denied-text",
                policy.evaluate(event("mcp:inventory/lookup", "{\"q\":\"\\u0073ecret\"}"))
                        .ruleId());
        assertEquals(
                "tool-argument-policy",
                policy.evaluate(event("mcp:inventory/lookup", "{\"q\":7}")).ruleId());
        assertEquals(
                "invalid-tool-arguments",
                policy.evaluate(event("mcp:inventory/lookup", "{\"q\":\"a\",\"q\":\"b\"}"))
                        .ruleId());
        assertEquals("tool-not-allowed", policy.evaluate(event("mcp:other/lookup", "{}")).ruleId());
    }

    private SecurityEvent event(String name, String arguments) {
        return new SecurityEvent(SecurityEvent.Phase.MCP_TOOL_INPUT, name, arguments);
    }
}
