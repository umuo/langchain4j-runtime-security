package io.agentsecurity.core;

/** 不可变检测决策；固定规则标识用于业务错误识别和脱敏审计。 */
public record Decision(boolean allowed, String ruleId, String policyVersion) {

    /** 保留原有两参数构造，未使用版本化策略时审计沿用宿主静态版本。 */
    public Decision(boolean allowed, String ruleId) {
        this(allowed, ruleId, null);
    }

    public Decision {
        if (policyVersion != null && !policyVersion.matches("[a-zA-Z0-9_.-]{1,80}")) {
            throw new IllegalArgumentException("Invalid decision policy version");
        }
        if (ruleId == null || !ruleId.matches("[a-zA-Z0-9_.-]{1,80}")) {
            throw new IllegalArgumentException(
                    "Rule ID must be a bounded identifier, not descriptive or sensitive text");
        }
    }

    public static Decision allow() {
        return new Decision(true, "allow");
    }

    public static Decision deny(String ruleId) {
        return new Decision(false, ruleId);
    }
}
