package io.agentsecurity.core;

public final class SecurityBlockedException extends RuntimeException {
    private final String ruleId;
    public SecurityBlockedException(String ruleId) {
        super("Agent security blocked operation: " + ruleId);
        this.ruleId = ruleId;
    }
    public String ruleId() { return ruleId; }
}
