package io.agentsecurity.policy;

import io.agentsecurity.core.*;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class ContextToolPolicyTest {
    static final String POLICY = """
        {"schemaVersion":1,"permissions":{"lookup":["customers:read"]},"tools":{
          "lookup":{"type":"object","required":["tenantId","user"],"properties":{
            "tenantId":{"type":"string","equalsContext":"tenantId"},
            "user":{"type":"string","equalsContext":"principalId"}
          }}
        }}
        """;
    static final SecurityContext AUTH = SecurityContext.authenticated("tenant-a", "user-a", Set.of("customers:read"));
    static Decision check(SecurityContext context, String args) {
        return ToolPolicy.fromJson(POLICY).evaluate(new SecurityEvent(UUID.randomUUID(), SecurityEvent.Phase.TOOL_INPUT, "lookup", args, context));
    }
    @Test void identityAndPermissionsMustComeFromAuthenticatedContext() {
        String args = "{\"tenantId\":\"tenant-a\",\"user\":\"user-a\"}";
        assertEquals("missing-security-context", check(null, args).ruleId());
        assertEquals("permission-denied", check(SecurityContext.authenticated("tenant-a", "user-a", Set.of()), args).ruleId());
        assertTrue(check(AUTH, args).allowed());
        assertEquals("tool-argument-policy", check(AUTH, "{\"tenantId\":\"tenant-b\",\"user\":\"user-a\"}").ruleId());
        assertEquals("tool-argument-policy", check(AUTH, "{\"tenantId\":\"tenant-a\",\"user\":\"user-b\"}").ruleId());
        assertTrue(check(AUTH, "{\"tenantId\":\"tenant-\\u0061\",\"user\":\"user-a\"}").allowed());
    }
    @Test void invalidBindingsAndPermissionDefinitionsFailAtLoad() {
        assertThrows(IllegalArgumentException.class, () -> ToolPolicy.fromJson(POLICY.replace("\"equalsContext\":\"tenantId\"", "\"equalsContext\":null")));
        assertThrows(IllegalArgumentException.class, () -> ToolPolicy.fromJson(POLICY.replace("\"equalsContext\":\"tenantId\"", "\"equalsContext\":\"memoryId\"")));
        assertThrows(IllegalArgumentException.class, () -> ToolPolicy.fromJson(POLICY.replace("[\"customers:read\"]", "[]")));
        assertThrows(IllegalArgumentException.class, () -> ToolPolicy.fromJson(POLICY.replace("\"permissions\":{\"lookup\"", "\"permissions\":{\"unknown\"")));
    }
    @Test void nestedBindingsStillRequireContextEvenWithoutPermissions() {
        ToolPolicy policy = ToolPolicy.fromJson("""
                {"schemaVersion":1,"tools":{"t":{"type":"object","properties":{
                    "tenants":{"type":"array","items":{"type":"string","equalsContext":"tenantId"}}
                }}}}
                """);
        assertEquals("missing-security-context", policy.evaluate(new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "t", "{}")).ruleId());
        assertEquals("tool-argument-policy", policy.evaluate(new SecurityEvent(UUID.randomUUID(), SecurityEvent.Phase.TOOL_INPUT,
                "t", "{\"tenants\":[\"tenant-a\",\"tenant-b\"]}", AUTH)).ruleId());
    }
}
