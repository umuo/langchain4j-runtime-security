package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.RagBridge;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import java.util.concurrent.CompletableFuture;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** 异步检索与增强入口，拒绝以失败 future 交付，并保留调用时的身份快照。 */
public final class RagFutureAdvice {

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static Throwable enter(
            @Advice.This Object source,
            @Advice.Argument(0) Object request,
            @Advice.Origin("#m") String method,
            @Advice.Local("ragContext") SecurityContext context) {
        context = SecurityContexts.current();
        try {
            RagBridge.before(source, request, method);
            return null;
        } catch (SecurityBlockedException denied) {
            return denied;
        }
    }

    @Advice.OnMethodExit
    public static void exit(
            @Advice.This Object source,
            @Advice.Argument(0) Object request,
            @Advice.Origin("#m") String method,
            @Advice.Enter Throwable denied,
            @Advice.Local("ragContext") SecurityContext context,
            @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
        result =
                denied != null
                        ? CompletableFuture.failedFuture(denied)
                        : RagBridge.guardFuture(
                                source, request, method, (CompletableFuture<?>) result, context);
    }
}
