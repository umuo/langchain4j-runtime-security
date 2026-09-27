package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.RagBridge;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** 包装 AI Services 注册的检索与增强组件，覆盖无法直接增强的隐藏 lambda 分发。 */
public final class RagRegistrationAdvice {

    @Advice.OnMethodEnter
    public static void enter(
            @Advice.Origin("#m") String method,
            @Advice.Argument(value = 0, readOnly = false, typing = Assigner.Typing.DYNAMIC)
                    Object component) {
        component =
                method.equals("contentRetriever")
                        ? RagBridge.wrap(component, RagBridge.RETRIEVER, "retrieve")
                        : RagBridge.wrap(component, RagBridge.AUGMENTOR, "augment");
    }
}
