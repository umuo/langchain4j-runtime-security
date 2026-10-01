package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.mcp.*;
import java.net.http.HttpClient;
import net.bytebuddy.asm.Advice;

/** 构造完成时替换 MCP 自有 HTTP 客户端，不修改全局 HTTP 行为。 */
public final class McpHttpLimitAdvice {
    @Advice.OnMethodExit
    public static void exit(
            @Advice.This Object transport,
            @Advice.FieldValue(value = "httpClient", readOnly = false) HttpClient client) {
        client = new LimitedMcpHttpClient(client, McpResponseLimits.state(transport));
    }
}
