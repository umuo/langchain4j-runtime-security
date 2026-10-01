package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.mcp.McpResponseLimits;
import net.bytebuddy.asm.Advice;

/** 只在官方 stdio start 创建读取器时注入有界输入流。 */
public final class McpStdioStartAdvice {
    @Advice.OnMethodEnter
    public static McpResponseLimits.State enter(@Advice.This Object transport) {
        return McpResponseLimits.enterStdio(transport);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Enter McpResponseLimits.State previous) {
        McpResponseLimits.exitStdio(previous);
    }
}
