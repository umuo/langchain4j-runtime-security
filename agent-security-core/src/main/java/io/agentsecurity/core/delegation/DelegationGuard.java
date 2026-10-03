package io.agentsecurity.core.delegation;

import io.agentsecurity.core.Decision;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityEvent;

/** 引擎固定前置检查，不能被插件 allow 覆盖；普通未委托上下文维持原有行为。 */
public final class DelegationGuard {
    private DelegationGuard() {}

    /** 首次入口检查扣减预算；最终放行前的重复授权检查只调用 evaluate。 */
    public static Decision begin(SecurityEvent event) {
        var decision = evaluate(event);
        if (!decision.allowed()
                || event.context() == null
                || event.context().invocation() == null) {
            return decision;
        }
        boolean charged =
                switch (event.phase()) {
                    case MODEL_INPUT,
                                    TOOL_INPUT,
                                    MCP_TOOL_INPUT,
                                    MCP_RESOURCE_INPUT,
                                    MCP_PROMPT_INPUT,
                                    MCP_DISCOVERY_INPUT,
                                    RETRIEVAL_INPUT,
                                    AUGMENTATION_INPUT,
                                    MEMORY_READ_INPUT,
                                    MEMORY_WRITE,
                                    MEMORY_DELETE ->
                            true;
                    default -> false;
                };
        if (charged) {
            try {
                event.context().invocation().runtime.consumeProtectedCheck(event.context());
            } catch (SecurityBlockedException denied) {
                return Decision.deny(denied.ruleId());
            }
        }
        return decision;
    }

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
            case TOOL_INPUT,
                            TOOL_OUTPUT,
                            MCP_TOOL_INPUT,
                            MCP_TOOL_OUTPUT,
                            MCP_RESOURCE_INPUT,
                            MCP_RESOURCE_OUTPUT,
                            MCP_PROMPT_INPUT,
                            MCP_PROMPT_OUTPUT,
                            MCP_DISCOVERY_INPUT,
                            MCP_DISCOVERY_OUTPUT ->
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
