package io.agentsecurity.telemetry;

import io.agentsecurity.core.telemetry.SecurityTelemetry;

/** Prometheus text 0.0.4 渲染器；HTTP 端点、认证和访问控制由宿主提供。 */
public final class PrometheusMetrics {
    public static final String CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";
    private static final String[] BOUNDS = {"0.001", "0.01", "0.1", "1", "+Inf"};

    private PrometheusMetrics() {}

    public static String render(SecurityTelemetry telemetry, OtlpLogExporter exporter) {
        var snapshot = telemetry.snapshot();
        var text = new StringBuilder();
        text.append("# TYPE agent_security_events_total counter\n");
        var histogram =
                new StringBuilder("# TYPE agent_security_check_duration_seconds histogram\n");
        for (var metric : snapshot.metrics()) {
            String labels =
                    "phase=\""
                            + metric.phase().name()
                            + "\",outcome=\""
                            + metric.outcome().name()
                            + "\"";
            text.append("agent_security_events_total{")
                    .append(labels)
                    .append("} ")
                    .append(metric.count())
                    .append('\n');
            long cumulative = 0;
            for (int i = 0; i < BOUNDS.length; i++) {
                cumulative += metric.durationBuckets().get(i);
                histogram
                        .append("agent_security_check_duration_seconds_bucket{")
                        .append(labels)
                        .append(",le=\"")
                        .append(BOUNDS[i])
                        .append("\"} ")
                        .append(cumulative)
                        .append('\n');
            }
            // 从桶生成 count，确保每次抓取的 +Inf 与 count 一致。
            histogram
                    .append("agent_security_check_duration_seconds_count{")
                    .append(labels)
                    .append("} ")
                    .append(cumulative)
                    .append('\n');
            histogram
                    .append("agent_security_check_duration_seconds_sum{")
                    .append(labels)
                    .append("} ")
                    .append(metric.durationNanosTotal() / 1e9)
                    .append('\n');
        }
        text.append(histogram);
        scalar(text, "agent_security_telemetry_dropped_total", "counter", snapshot.dropped());
        scalar(text, "agent_security_telemetry_queued", "gauge", snapshot.queued());
        if (exporter != null) {
            var health = exporter.health();
            scalar(text, "agent_security_export_running", "gauge", exporter.isRunning() ? 1 : 0);
            scalar(text, "agent_security_export_attempts_total", "counter", health.attempts());
            scalar(text, "agent_security_export_failures_total", "counter", health.failures());
            scalar(text, "agent_security_export_timeouts_total", "counter", health.timeouts());
            scalar(text, "agent_security_export_accepted_total", "counter", health.accepted());
            scalar(text, "agent_security_export_dropped_total", "counter", health.dropped());
            scalar(text, "agent_security_export_pending", "gauge", health.pending());
        }
        return text.toString();
    }

    /** 显式传入一个运行时；多运行时宿主应分别暴露或聚合，不以 run UUID 作为标签。 */
    public static String render(
            SecurityTelemetry telemetry,
            OtlpLogExporter exporter,
            io.agentsecurity.core.delegation.AgentRuntime runtime) {
        var text = new StringBuilder(render(telemetry, exporter));
        var state = runtime.snapshot();
        scalar(text, "agent_security_invocations_active", "gauge", state.activeInvocations());
        scalar(text, "agent_security_delegation_depth_max", "gauge", state.maxDepth());
        text.append("# TYPE agent_security_invocations_ended_total counter\n");
        for (var reason : io.agentsecurity.core.delegation.AgentEndReason.values()) {
            text.append("agent_security_invocations_ended_total{reason=\"")
                    .append(reason.name())
                    .append("\"} ")
                    .append(state.ended().getOrDefault(reason, 0L))
                    .append('\n');
        }
        return text.toString();
    }

    /** 独立诊断指标片段；宿主可与 render 结果拼接，只暴露一个引擎或先自行聚合。 */
    public static String renderHealth(
            io.agentsecurity.core.health.WorkerHealth detector,
            io.agentsecurity.core.health.WorkerHealth audit,
            io.agentsecurity.core.health.AgentCoverage.Snapshot coverage) {
        var text = new StringBuilder();
        worker(text, "detector", detector);
        worker(text, "audit", audit);
        if (coverage != null) {
            scalar(
                    text,
                    "agent_security_version_checks_passed_total",
                    "counter",
                    coverage.versionChecksPassed());
            scalar(
                    text,
                    "agent_security_version_checks_failed_total",
                    "counter",
                    coverage.versionChecksFailed());
            scalar(
                    text,
                    "agent_security_instrumentation_installed",
                    "gauge",
                    coverage.installed() ? 1 : 0);
            scalar(
                    text,
                    "agent_security_instrumentation_failed",
                    "gauge",
                    coverage.failed() ? 1 : 0);
            scalar(
                    text,
                    "agent_security_transformations_total",
                    "counter",
                    coverage.transformations());
            scalar(
                    text,
                    "agent_security_transformation_failure_signals_total",
                    "counter",
                    coverage.failures());
            scalar(
                    text,
                    "agent_security_transformed_names_omitted_total",
                    "counter",
                    coverage.omittedNames());
        }
        return text.toString();
    }

    /** 独立 MCP 诊断片段；只有固定原因标签，未接 Agent 时不代表已提供保护。 */
    public static String renderMcp(io.agentsecurity.core.health.McpDiagnostics.Snapshot state) {
        if (state == null) {
            return "";
        }
        var text = new StringBuilder("# TYPE agent_security_mcp_limit_rejections_total counter\n");
        for (var reason : io.agentsecurity.core.health.McpDiagnostics.Limit.values()) {
            text.append("agent_security_mcp_limit_rejections_total{reason=\"")
                    .append(reason.name())
                    .append("\"} ")
                    .append(state.limits().getOrDefault(reason, 0L))
                    .append('\n');
        }
        scalar(
                text,
                "agent_security_mcp_transport_failures_total",
                "counter",
                state.transportFailures());
        scalar(
                text,
                "agent_security_mcp_failed_state_checks_total",
                "counter",
                state.failedStateChecks());
        scalar(
                text,
                "agent_security_mcp_pagination_started_total",
                "counter",
                state.paginationStarted());
        scalar(
                text,
                "agent_security_mcp_pagination_completed_total",
                "counter",
                state.paginationCompleted());
        scalar(
                text,
                "agent_security_mcp_pagination_failed_total",
                "counter",
                state.paginationFailed());
        scalar(text, "agent_security_mcp_pages_requested_total", "counter", state.pagesRequested());
        scalar(text, "agent_security_mcp_pages_accepted_total", "counter", state.pagesAccepted());
        scalar(text, "agent_security_mcp_items_accepted_total", "counter", state.itemsAccepted());
        scalar(
                text,
                "agent_security_mcp_json_bytes_accepted_total",
                "counter",
                state.jsonBytesAccepted());
        return text.toString();
    }

    private static void worker(
            StringBuilder text, String kind, io.agentsecurity.core.health.WorkerHealth state) {
        if (state == null) {
            return;
        }
        String prefix = "agent_security_" + kind + "_";
        scalar(text, prefix + "active", "gauge", state.active());
        scalar(text, prefix + "queued", "gauge", state.queued());
        scalar(text, prefix + "concurrency", "gauge", state.concurrency());
        scalar(text, prefix + "queue_capacity", "gauge", state.capacity());
        scalar(text, prefix + "closed", "gauge", state.closed() ? 1 : 0);
        scalar(text, prefix + "failed", "gauge", state.failed() ? 1 : 0);
        scalar(text, prefix + "timeouts_total", "counter", state.timeouts());
        scalar(text, prefix + "errors_total", "counter", state.errors());
        scalar(text, prefix + "rejected_total", "counter", state.rejected());
        scalar(text, prefix + "interrupted_total", "counter", state.interrupted());
    }

    private static void scalar(StringBuilder text, String name, String type, long value) {
        text.append("# TYPE ").append(name).append(' ').append(type).append('\n');
        text.append(name).append(' ').append(value).append('\n');
    }
}
