package io.agentsecurity.telemetry;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.health.AgentCoverage;
import io.agentsecurity.core.health.WorkerHealth;
import org.junit.jupiter.api.Test;

class HealthMetricsTest {
    @Test
    void metricsOmitUnknownWorkersAndClassNames() {
        var coverage = new AgentCoverage();
        coverage.transformed("private.CustomerModel");
        coverage.transformationFailed();
        var worker = new WorkerHealth(1, 2, 4, 4, false, false, 3, 5, 7, 0);
        var text = PrometheusMetrics.renderHealth(worker, null, coverage.snapshot());
        assertTrue(text.contains("agent_security_detector_timeouts_total 3\n"));
        assertTrue(text.contains("agent_security_detector_queued 2\n"));
        assertTrue(text.contains("agent_security_instrumentation_failed 1\n"));
        assertFalse(text.contains("agent_security_audit_"));
        assertFalse(text.contains("CustomerModel"));
        assertEquals("", PrometheusMetrics.renderHealth(null, null, null));
    }
}
