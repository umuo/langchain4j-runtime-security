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

    private static void scalar(StringBuilder text, String name, String type, long value) {
        text.append("# TYPE ").append(name).append(' ').append(type).append('\n');
        text.append(name).append(' ').append(value).append('\n');
    }
}
