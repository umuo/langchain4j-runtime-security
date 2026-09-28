package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.McpBridge;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import net.bytebuddy.asm.Advice;

/** 在发送 MCP 工具请求前检查，并在结果交付前复核。 */
public final class McpSyncAdvice {
    @Advice.OnMethodEnter
    public static String enter(
            @Advice.This Object source,
            @Advice.Argument(0) Object request,
            @Advice.Local("mcpContext") SecurityContext context) {
        context = SecurityContexts.current();
        return McpBridge.before(source, request);
    }

    @Advice.OnMethodExit
    public static void exit(
            @Advice.Argument(0) Object request,
            @Advice.Enter String operation,
            @Advice.Return Object result,
            @Advice.Local("mcpContext") SecurityContext context) {
        try (var scope = SecurityContexts.restore(context)) {
            McpBridge.after(request, operation, result);
        }
    }
}
