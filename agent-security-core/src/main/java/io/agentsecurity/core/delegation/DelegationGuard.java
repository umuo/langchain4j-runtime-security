package io.agentsecurity.core.delegation;

import io.agentsecurity.core.Decision;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityEvent;

/** 引擎固定前置检查，不能被插件 allow 覆盖；普通未委托上下文维持原有行为。 */
public final class DelegationGuard {
    private DelegationGuard() {}

    public static Decision evaluate(SecurityEvent event) {
        var context = event.context();
        if (context == null || context.invocation() == null) {
            return Decision.allow();
        }
        var invocation = context.invocation();
        try {
            invocation.runtime.requireActive(context);
        } catch (SecurityBlockedException denied) {
            return Decision.deny(denied.ruleId());
        }
        var grant = invocation.grant();
        return switch (event.phase()) {
            case TOOL_INPUT, TOOL_OUTPUT ->
                    grant.tools().contains(event.operation())
                            ? Decision.allow()
                            : Decision.deny("agent-tool-denied");
            case RETRIEVAL_INPUT, RETRIEVAL_OUTPUT ->
                    grant.retrievers().contains(event.operation())
                            ? Decision.allow()
                            : Decision.deny("agent-retriever-denied");
            case MEMORY_READ_INPUT, MEMORY_READ_OUTPUT, MEMORY_WRITE, MEMORY_DELETE ->
                    event.resource() != null && grant.memoryResources().contains(event.resource())
                            ? Decision.allow()
                            : Decision.deny("agent-memory-denied");
            default -> Decision.allow();
        };
    }
}
