package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.McpContentBridge;
import net.bytebuddy.asm.Advice;

/** 同步资源读取和提示词渲染边界；先授权，后检查整批返回内容。 */
public final class McpContentAdvice {
    @Advice.OnMethodEnter
    public static McpContentBridge.Boundary enter(
            @Advice.This Object client,
            @Advice.Origin("#m") String method,
            @Advice.AllArguments Object[] arguments) {
        return McpContentBridge.before(client, method, arguments);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(
            @Advice.This Object client,
            @Advice.Enter McpContentBridge.Boundary boundary,
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
            McpContentBridge.after(client, boundary, result);
        }
    }
}
