package io.agentsecurity.core;

public record Decision(boolean allowed, String ruleId) {
    public Decision {
        if (ruleId == null || !ruleId.matches("[a-zA-Z0-9_.-]{1,80}"))
            throw new IllegalArgumentException("Rule ID must be a bounded identifier, not descriptive or sensitive text");
    }
    public static Decision allow() { return new Decision(true, "allow"); }
    public static Decision deny(String ruleId) { return new Decision(false, ruleId); }
}
