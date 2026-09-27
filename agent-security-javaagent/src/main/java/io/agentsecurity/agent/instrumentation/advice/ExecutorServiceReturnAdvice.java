package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.core.SecurityContexts;
import net.bytebuddy.asm.Advice;

/** 包装框架默认 ExecutorService，保留生命周期接口并传播任务提交时的身份。 */
public final class ExecutorServiceReturnAdvice {

    @Advice.OnMethodExit
    public static void exit(
            @Advice.Return(readOnly = false) java.util.concurrent.ExecutorService executor) {
        executor = SecurityContexts.executorService(executor);
    }
}
