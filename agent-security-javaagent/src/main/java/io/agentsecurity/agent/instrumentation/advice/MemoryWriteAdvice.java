package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.MemoryBridge;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** 记忆写入和删除前置检查；批量参数以已检查快照替换，避免遍历结果变化或提前修改状态。 */
public final class MemoryWriteAdvice {

    @Advice.OnMethodEnter
    public static void enter(
            @Advice.This Object source,
            @Advice.Origin("#m") String method,
            @Advice.AllArguments(readOnly = false, typing = Assigner.Typing.DYNAMIC)
                    Object[] args) {
        Object[] replacement = args.clone();
        MemoryBridge.before(source, method, replacement);
        args = replacement;
    }
}
