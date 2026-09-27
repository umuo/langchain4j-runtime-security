package io.agentsecurity.core;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** 应用认证入口提供的不可变身份快照。工厂方法不验证凭证，禁止从模型输出构造可信身份。 */
public record SecurityContext(
        UUID runId, String tenantId, String principalId, Set<String> permissions) {

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
