package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.core.SecurityContexts;
import net.bytebuddy.asm.Advice;

/** 包装框架默认 Executor，在提交任务时捕获上下文。 */
public final class ExecutorReturnAdvice {

    @Advice.OnMethodExit
    public static void exit(
            @Advice.Return(readOnly = false) java.util.concurrent.Executor executor) {
        executor = SecurityContexts.executor(executor);
    }
}
