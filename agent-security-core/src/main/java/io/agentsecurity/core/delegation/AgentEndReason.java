package io.agentsecurity.core.delegation;

/** 可信运行时赋予的终止原因；终止委托不代表外部 I/O 已停止或回滚。 */
public enum AgentEndReason {
    COMPLETED,
    FAILED,
    RELEASED,
    CANCELLED,
    BUDGET_EXHAUSTED,
    EXECUTOR_REJECTED,
    REVOKED,
    PARENT_FINISHED,
    PARENT_REVOKED,
    EXPIRED,
    RUNTIME_CLOSED,
    AUDIT_FAILED
}
