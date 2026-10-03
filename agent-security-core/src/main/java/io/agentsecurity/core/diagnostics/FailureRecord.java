package io.agentsecurity.core.diagnostics;

import io.agentsecurity.core.SecurityEvent;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** 脱敏故障快照。不持有 Throwable、身份对象、业务操作名、正文或资源地址。 */
public record FailureRecord(
        UUID id,
        Instant timestamp,
        Category category,
        Stage stage,
        Boundary boundary,
        SecurityEvent.Phase phase,
        UUID eventId,
        UUID runId,
        UUID invocationId,
        UUID parentInvocationId,
        int depth,
        String ruleFingerprint,
        String policyFingerprint) {
    public enum Category {
        AUTHENTICATION_FAILURE,
        SESSION_FAILURE,
        DESTINATION_FAILURE,
        POLICY_DENIED,
        DETECTOR_FAILURE,
        AUDIT_FAILURE,
        TIMEOUT,
        CAPACITY_LIMIT,
        UNSUPPORTED,
        TRANSPORT_FAILURE,
        CANCELLED,
        EXECUTION_FAILURE,
        INSTRUMENTATION_FAILURE
    }

    public enum Boundary {
        MODEL,
        TOOL,
        MCP_TOOL,
        MCP_RESOURCE,
        MCP_PROMPT,
        MCP_DISCOVERY,
        RETRIEVAL,
        AUGMENTATION,
        MEMORY,
        AGENT,
        UNKNOWN
    }

    public enum Stage {
        POLICY_EVALUATION,
        MCP_INPUT,
        MCP_EXECUTION,
        MCP_OUTPUT,
        INSTRUMENTATION
    }

    public FailureRecord {
        Objects.requireNonNull(id);
        Objects.requireNonNull(timestamp);
        Objects.requireNonNull(category);
        Objects.requireNonNull(stage);
        Objects.requireNonNull(boundary);
        if (depth < 0 || !fingerprint(ruleFingerprint) || !fingerprint(policyFingerprint)) {
            throw new IllegalArgumentException("Invalid failure record");
        }
    }

    private static boolean fingerprint(String value) {
        return value == null || value.matches("[0-9a-f]{64}");
    }
}
