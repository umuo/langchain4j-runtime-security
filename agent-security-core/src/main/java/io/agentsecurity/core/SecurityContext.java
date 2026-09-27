package io.agentsecurity.core;

import io.agentsecurity.core.delegation.AgentInvocation;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** 应用认证入口提供的不可变身份快照。工厂方法不验证凭证，禁止从模型输出构造可信身份。 */
public record SecurityContext(
        UUID runId,
        String tenantId,
        String principalId,
        Set<String> permissions,
        AgentInvocation invocation) {

    public SecurityContext {
        Objects.requireNonNull(runId);
        if (!identifier(tenantId) || !identifier(principalId)) {
            throw new IllegalArgumentException("Invalid security identity identifier");
        }
        permissions = Set.copyOf(permissions);
        if (permissions.size() > 128
                || !permissions.stream().allMatch(SecurityContext::identifier)) {
            throw new IllegalArgumentException("Invalid security permissions");
        }
    }

    /** 保留普通身份的四参数构造入口；委托句柄只由可信调度器签发。 */
    public SecurityContext(
            UUID runId, String tenantId, String principalId, Set<String> permissions) {
        this(runId, tenantId, principalId, permissions, null);
    }

    public static SecurityContext authenticated(
            String tenantId, String principalId, Set<String> permissions) {
        return new SecurityContext(UUID.randomUUID(), tenantId, principalId, permissions);
    }

    private static boolean identifier(String value) {
        return value != null && value.matches("[a-zA-Z0-9@._:-]{1,128}");
    }

    @Override
    public String toString() {
        return "SecurityContext[runId=" + runId + "]";
    }
}
