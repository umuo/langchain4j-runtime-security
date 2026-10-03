package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.McpDiscoveryBridge;
import net.bytebuddy.asm.Advice;

/** 即使命中客户端缓存也检查发现结果，防止缓存绕过当前调用者权限。 */
public final class McpDiscoveryAdvice {
    @Advice.OnMethodEnter
    public static McpDiscoveryBridge.Boundary enter(
            @Advice.This Object client, @Advice.Origin("#m") String method) {
        return McpDiscoveryBridge.before(client, method);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(
            @Advice.This Object client,
            @Advice.Enter McpDiscoveryBridge.Boundary boundary,
            @Advice.Return Object result,
            @Advice.Origin("#m") String method,
            @Advice.Thrown Throwable failure) {
        if (failure != null) {
            io.agentsecurity.agent.bridge.McpFailureBridge.record(
                    failure,
                    method,
                    io.agentsecurity.core.diagnostics.FailureRecord.Stage.MCP_EXECUTION,
                    boundary.context());
        } else {
            McpDiscoveryBridge.after(client, boundary, result);
        }
    }
}
