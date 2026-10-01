package io.agentsecurity.telemetry;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.health.McpDiagnostics;
import org.junit.jupiter.api.Test;

class McpMetricsTest {
    @Test
    void renderUsesOnlyFixedReasonsAndDoesNotConsumeTheSnapshot() {
        var diagnostics = new McpDiagnostics();
        diagnostics.limit(McpDiagnostics.Limit.PAGINATION_ITEMS);
        diagnostics.transportFailed();
        diagnostics.failedStateChecked();
        diagnostics.paginationStarted();
        diagnostics.pageRequested();
        diagnostics.pageAccepted(3, 42);
        diagnostics.paginationFinished(false);
        var state = diagnostics.snapshot();
        String text = PrometheusMetrics.renderMcp(state);
        assertTrue(
                text.contains(
                        "agent_security_mcp_limit_rejections_total{reason=\"PAGINATION_ITEMS\"} 1\n"));
        assertTrue(text.contains("agent_security_mcp_transport_failures_total 1\n"));
        assertTrue(text.contains("agent_security_mcp_pagination_failed_total 1\n"));
        assertTrue(text.contains("agent_security_mcp_json_bytes_accepted_total 42\n"));
        assertEquals(text, PrometheusMetrics.renderMcp(state));
        assertEquals("", PrometheusMetrics.renderMcp(null));
        assertEquals(
                McpDiagnostics.Limit.values().length,
                text.lines()
                        .filter(
                                line ->
                                        line.startsWith(
                                                "agent_security_mcp_limit_rejections_total{"))
                        .count());
    }
}
