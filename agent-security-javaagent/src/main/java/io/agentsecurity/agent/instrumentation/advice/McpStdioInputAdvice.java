package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.mcp.McpResponseLimits;
import java.io.InputStream;
import net.bytebuddy.asm.Advice;

/** 在 InputStreamReader 和 BufferedReader 分配完整行之前包装输入。 */
public final class McpStdioInputAdvice {
    @Advice.OnMethodEnter
    public static void enter(@Advice.Argument(value = 0, readOnly = false) InputStream input) {
        input = McpResponseLimits.wrapStdio(input);
    }
}
