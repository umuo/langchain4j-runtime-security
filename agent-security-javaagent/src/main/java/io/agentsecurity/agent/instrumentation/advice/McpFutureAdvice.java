package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.McpBridge;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import java.util.concurrent.CompletableFuture;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** 异步拒绝通过失败 future 交付，返回检查沿用入口身份。 */
public final class McpFutureAdvice {
    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static Throwable enter(
            @Advice.This Object source,
            @Advice.Argument(0) Object request,
            @Advice.Local("mcpContext") SecurityContext context,
            @Advice.Local("mcpOperation") String operation) {
        context = SecurityContexts.current();
        try {
            operation = McpBridge.before(source, request);
            return null;
        } catch (SecurityBlockedException denied) {
            return denied;
        }
    }

    @Advice.OnMethodExit
    public static void exit(
            @Advice.This Object client,
            @Advice.Argument(0) Object request,
            @Advice.Enter Throwable denied,
            @Advice.Local("mcpContext") SecurityContext context,
            @Advice.Local("mcpOperation") String operation,
            @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
        result =
                denied != null
                        ? CompletableFuture.failedFuture(denied)
                        : McpBridge.guardFuture(
                                client, request, operation, (CompletableFuture<?>) result, context);
    }
}
