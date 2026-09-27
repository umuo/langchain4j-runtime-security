package io.agentsecurity.core.delegation;

import io.agentsecurity.core.SecurityContext;

/** 只输出已约束的 Agent 标签及随机关联 ID，不输出权限、资源、用户或任务正文。 */
public final class AgentAuditFields {
    private AgentAuditFields() {}

    public static String json(SecurityContext context) {
        var invocation = context == null ? null : context.invocation();
        if (invocation == null) {
            return ",\"agentId\":null,\"invocationId\":null,\"parentInvocationId\":null,\"delegationId\":null";
        }
        return ",\"agentId\":\""
                + invocation.agentId()
                + "\",\"invocationId\":\""
                + invocation.invocationId()
                + "\",\"parentInvocationId\":"
                + (invocation.parentInvocationId() == null
                        ? "null"
                        : "\"" + invocation.parentInvocationId() + "\"")
                + ",\"delegationId\":\""
                + invocation.delegationId()
                + "\"";
    }
}
