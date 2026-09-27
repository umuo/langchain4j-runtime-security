package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.Bridge;
import net.bytebuddy.asm.Advice;

/** 同步模型与工具入口：执行前检查请求，成功返回后检查结果。 */
public final class SyncAdvice {

    @Advice.OnMethodEnter
    public static void enter(@Advice.Argument(0) Object request) {
        Bridge.before(request);
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Argument(0) Object request, @Advice.Return Object result) {
        Bridge.after(request, result);
    }
}
