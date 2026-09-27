package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.MemoryBridge;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** 包装窗口记忆注册的存储接口，补充代理存储的调用边界检查。 */
public final class MemoryStoreRegistrationAdvice {

    @Advice.OnMethodEnter
    public static void enter(
            @Advice.Argument(value = 0, readOnly = false, typing = Assigner.Typing.DYNAMIC)
                    Object store) {
        store = MemoryBridge.wrap(store, MemoryBridge.STORE);
    }
}
