package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.MemoryBridge;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** 包装框架返回的会话记忆，覆盖代理实现的标准分发入口。 */
public final class MemoryDispatchAdvice {

    @Advice.OnMethodExit
    public static void exit(
            @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
        result = MemoryBridge.wrap(result, MemoryBridge.MEMORY);
    }
}
