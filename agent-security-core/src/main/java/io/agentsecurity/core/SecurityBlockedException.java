package io.agentsecurity.core;

/** 安全拒绝异常。调用方应使用规则标识判断原因，不得吞掉异常后继续执行受保护操作。 */
public final class SecurityBlockedException extends RuntimeException {

    private final String ruleId;

    public SecurityBlockedException(String ruleId) {
        super("Agent security blocked operation: " + ruleId);
        this.ruleId = ruleId;
    }

    public String ruleId() {
        return ruleId;
    }
}
