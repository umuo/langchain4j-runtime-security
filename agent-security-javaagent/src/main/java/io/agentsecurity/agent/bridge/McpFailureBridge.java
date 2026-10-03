package io.agentsecurity.agent.bridge;

import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityEvent;
import io.agentsecurity.core.diagnostics.FailureDiagnostics;
import io.agentsecurity.core.diagnostics.FailureRecord.Stage;

/** 只记录固定阶段和已捕获身份；不传入 MCP 请求、URI、工具名或异常消息。 */
public final class McpFailureBridge {
    private McpFailureBridge() {}

    public static void record(
            Throwable failure, String method, Stage stage, SecurityContext context) {
        if (failure == null) {
            return;
        }
        boolean output = stage == Stage.MCP_OUTPUT;
        SecurityEvent.Phase phase =
                switch (method) {
                    case "readResource" ->
                            output
                                    ? SecurityEvent.Phase.MCP_RESOURCE_OUTPUT
                                    : SecurityEvent.Phase.MCP_RESOURCE_INPUT;
                    case "getPrompt" ->
                            output
                                    ? SecurityEvent.Phase.MCP_PROMPT_OUTPUT
                                    : SecurityEvent.Phase.MCP_PROMPT_INPUT;
                    case "executeTool", "executeToolAsync" ->
                            output
                                    ? SecurityEvent.Phase.MCP_TOOL_OUTPUT
                                    : SecurityEvent.Phase.MCP_TOOL_INPUT;
                    default ->
                            output
                                    ? SecurityEvent.Phase.MCP_DISCOVERY_OUTPUT
                                    : SecurityEvent.Phase.MCP_DISCOVERY_INPUT;
                };
        // 执行阶段没有对应的检测事件，不把 INPUT 伪装成真实失败检测阶段。
        FailureDiagnostics.global().record(failure, stage, phase, context, null, null);
    }
}
