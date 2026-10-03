package io.agentsecurity.telemetry;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.*;
import io.agentsecurity.core.diagnostics.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class FailureExportTest {
    @Test
    void jsonAndMetricsUseWhitelistedFieldsWithoutSensitiveLabels() throws Exception {
        var diagnostics = new FailureDiagnostics(1);
        var identity = SecurityContext.authenticated("secret-tenant", "secret-user", Set.of());
        var record =
                diagnostics.record(
                        new SecurityBlockedException("secret-rule"),
                        FailureRecord.Stage.MCP_OUTPUT,
                        SecurityEvent.Phase.MCP_TOOL_OUTPUT,
                        identity,
                        UUID.randomUUID(),
                        "secret-version");
        diagnostics.instrumentationFailure();
        String json = FailureJson.encode(diagnostics.drain(1));
        assertTrue(json.contains("\"schemaVersion\":1"));
        assertTrue(json.contains(record.id().toString()));
        assertTrue(json.contains(identity.runId().toString()));
        assertTrue(json.contains(FailureDiagnostics.fingerprint("secret-version")));
        assertFalse(json.contains("secret"));
        try (var parser = new com.fasterxml.jackson.core.JsonFactory().createParser(json)) {
            while (parser.nextToken() != null) {
                /* 完整读取，验证生成的 JSON 结构有效。 */
            }
        }
        String metrics = PrometheusMetrics.renderFailures(diagnostics.snapshot());
        assertTrue(metrics.contains("category=\"POLICY_DENIED\",stage=\"MCP_OUTPUT\"} 1"));
        assertTrue(metrics.contains("agent_security_failure_records_dropped_total 1"));
        assertFalse(metrics.contains(identity.runId().toString()));
        assertFalse(metrics.contains(record.ruleFingerprint()));
        assertEquals("", PrometheusMetrics.renderFailures(null));
        assertThrows(
                IllegalArgumentException.class,
                () -> FailureJson.encode(Collections.nCopies(1025, record)));
    }
}
