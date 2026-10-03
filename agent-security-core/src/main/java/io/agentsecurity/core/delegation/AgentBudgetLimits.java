package io.agentsecurity.core.delegation;

/** 单棵根任务树的累计额度；子任务结束不返还额度，不等同于模型 token 或费用预算。 */
public record AgentBudgetLimits(int maxInvocations, long maxProtectedChecks) {
    public AgentBudgetLimits {
        if (maxInvocations < 1
                || maxInvocations > 10000
                || maxProtectedChecks < 1
                || maxProtectedChecks > 1000000) {
            throw new IllegalArgumentException("Invalid agent budget");
        }
    }

    public static AgentBudgetLimits defaults() {
        return new AgentBudgetLimits(10000, 1000000);
    }
}
