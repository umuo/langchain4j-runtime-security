package io.agentsecurity.core.delegation;

import java.util.Objects;
import java.util.Set;

/** 由可信宿主注册的 Agent 能力上限及可调用子 Agent 集合，不能由模型自行注册。 */
public record AgentDefinition(
        String agentId, AgentGrant maximumGrant, Set<String> allowedChildren) {
    public AgentDefinition {
        identifier(agentId);
        Objects.requireNonNull(maximumGrant);
        allowedChildren = Set.copyOf(allowedChildren);
        if (allowedChildren.size() > 128) {
            throw new IllegalArgumentException("Too many child definitions");
        }
        allowedChildren.forEach(AgentDefinition::identifier);
    }

    static void identifier(String value) {
        if (value == null || !value.matches("[a-zA-Z0-9@._:-]{1,128}")) {
            throw new IllegalArgumentException("Invalid agent identifier");
        }
    }
}
