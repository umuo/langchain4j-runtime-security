package io.agentsecurity.core;

/** 安全拒绝异常。调用方应使用规则标识判断原因，不得吞掉异常后继续执行受保护操作。 */
public final class SecurityBlockedException extends RuntimeException {

    private final String ruleId;
    private transient volatile io.agentsecurity.core.diagnostics.FailureRecord diagnostic;

    /** 已接入的最终拒绝边界提供快照；未接入的直接异常返回 null。 */
    public io.agentsecurity.core.diagnostics.FailureRecord diagnostic() {
        return diagnostic;
    }

    /** 只附加第一次最终诊断，供内置收集器去重；不替代强制审计。 */
    public synchronized boolean attachDiagnostic(
            io.agentsecurity.core.diagnostics.FailureRecord record) {
        java.util.Objects.requireNonNull(record);
        if (diagnostic != null) {
            return false;
        }
        diagnostic = record;
        return true;
    }

    public SecurityBlockedException(String ruleId) {
        super("Agent security blocked operation: " + ruleId);
        this.ruleId = ruleId;
    }

    public String ruleId() {
        return ruleId;
    }
}
