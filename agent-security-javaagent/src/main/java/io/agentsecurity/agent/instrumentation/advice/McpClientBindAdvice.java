package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.mcp.McpResponseLimits;
import net.bytebuddy.asm.Advice;

/** 将客户端与传输的容量故障状态绑定。 */
public final class McpClientBindAdvice {
    @Advice.OnMethodExit
    public static void exit(
            @Advice.This Object client, @Advice.FieldValue("transport") Object transport) {
        McpResponseLimits.bind(client, transport);
    }
}
