package io.agentsecurity.core.telemetry;

import io.agentsecurity.core.SecurityEvent;
import java.time.Instant;
import java.util.UUID;

/** 脱敏关联记录。不保留原始事件、身份、资源、规则文本或模型输入输出。 */
public record TelemetryRecord(
        Instant timestamp,
        UUID eventId,
        SecurityEvent.Phase phase,
        SecurityTelemetry.Outcome outcome,
        long durationNanos,
        UUID runId,
        UUID invocationId,
        UUID parentInvocationId,
        int depth,
        io.agentsecurity.core.delegation.AgentEndReason endReason,
        long lifetimeNanos) {}
