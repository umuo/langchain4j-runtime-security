package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.MemoryBridge;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** 记忆读取前授权、返回后检查整批内容；资源和身份使用进入方法时的快照。 */
public final class MemoryReadAdvice {

    @Advice.OnMethodEnter
    public static MemoryBridge.Call enter(
            @Advice.This Object source,
            @Advice.Origin("#m") String method,
            @Advice.AllArguments Object[] args) {
        return MemoryBridge.before(source, method, args);
    }

    @Advice.OnMethodExit
    public static void exit(
            @Advice.Enter MemoryBridge.Call call,
            @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
        result = MemoryBridge.after(call, result);
    }
}
