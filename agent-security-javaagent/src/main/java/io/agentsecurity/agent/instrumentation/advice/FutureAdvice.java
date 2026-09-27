package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.Bridge;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import java.util.concurrent.CompletableFuture;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** 异步模型与工具入口：输入拒绝转换为失败 future，输出检查保留调用时身份。 */
public final class FutureAdvice {

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static Throwable enter(
            @Advice.Argument(0) Object request,
            @Advice.Local("securityContext") SecurityContext context) {
        context = SecurityContexts.current();
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
            @Advice.Local("securityContext") SecurityContext context,
            @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
        result =
                denied != null
                        ? CompletableFuture.failedFuture(denied)
                        : Bridge.guardFuture(request, (CompletableFuture<?>) result, context);
    }
}
