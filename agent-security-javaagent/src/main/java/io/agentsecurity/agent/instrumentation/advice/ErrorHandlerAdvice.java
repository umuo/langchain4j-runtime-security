package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.core.SecurityBlockedException;
import net.bytebuddy.asm.Advice;

/** 从异常链中重新抛出安全拒绝，防止工具错误处理器将拒绝转换成模型可见的普通结果。 */
public final class ErrorHandlerAdvice {

    @Advice.OnMethodEnter
    public static void enter(@Advice.Argument(0) Exception error) {
        Throwable cause = error;
        for (int depth = 0; cause != null && depth < 64; depth++) {
            if (cause instanceof SecurityBlockedException denied) {
                throw denied;
            }
            if (cause.getCause() == cause) {
                break;
            }
            cause = cause.getCause();
        }
    }
}
