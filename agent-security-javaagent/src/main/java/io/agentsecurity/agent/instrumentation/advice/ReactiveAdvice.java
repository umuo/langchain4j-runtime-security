package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.Bridge;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContexts;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** 响应式模型入口：标准转发路径仅传播身份，实际 provider 边界负责完整内容检查。 */
public final class ReactiveAdvice {

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static Throwable enter(@Advice.Argument(0) Object request) {
        try {
            Bridge.before(request);
            return null;
        } catch (SecurityBlockedException denied) {
            return denied;
        }
    }

    @Advice.OnMethodExit
    public static void exit(
            @Advice.Argument(0) Object request,
            @Advice.Enter Throwable denied,
            @Advice.Origin("#t") String owner,
            @Advice.Origin("#m") String method,
            @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
        if (denied != null) {
            result = Bridge.failedPublisher(denied);
        } else // The standard cold chat publisher delegates to guarded doChat on each subscription.
        if (!owner.equals("dev.langchain4j.model.chat.StreamingChatModel")
                || !method.equals("chat")) {
            result =
                    Bridge.guardPublisher(request, (java.util.concurrent.Flow.Publisher<?>) result);
        } else {
            result =
                    Bridge.contextPublisher(
                            (java.util.concurrent.Flow.Publisher<?>) result,
                            SecurityContexts.current());
        }
    }
}
