package io.agentsecurity.core.delegation;

import java.time.Duration;

/** 限制同时登记的执行数、委托深度和最长存活时间；根执行深度为零。 */
public record AgentRuntimeLimits(int maxInvocations, int maxDepth, Duration maxLifetime) {
    public AgentRuntimeLimits {
        if (maxInvocations < 1
                || maxInvocations > 10000
                || maxDepth < 0
                || maxDepth > 32
                || maxLifetime == null
                || maxLifetime.isZero()
                || maxLifetime.isNegative()
                || maxLifetime.compareTo(Duration.ofHours(24)) > 0) {
            throw new IllegalArgumentException("Invalid agent runtime limits");
        }
    }

    public static AgentRuntimeLimits defaults() {
        return new AgentRuntimeLimits(256, 8, Duration.ofMinutes(5));
    }
}
