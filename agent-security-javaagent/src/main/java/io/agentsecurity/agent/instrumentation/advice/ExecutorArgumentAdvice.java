package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.core.SecurityContexts;
import net.bytebuddy.asm.Advice;

/** 包装自定义工具执行器，在提交任务时捕获身份，而非在线程创建时继承身份。 */
public final class ExecutorArgumentAdvice {

    @Advice.OnMethodEnter
    public static void enter(
            @Advice.Argument(value = 0, readOnly = false) java.util.concurrent.Executor executor) {
        if (executor != null) {
            executor = SecurityContexts.executor(executor);
        }
    }
}
