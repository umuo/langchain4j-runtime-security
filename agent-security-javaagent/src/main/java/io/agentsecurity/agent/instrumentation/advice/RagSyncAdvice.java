package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.RagBridge;
import net.bytebuddy.asm.Advice;

/** 同步检索与增强入口，执行前检查请求、返回后检查整批内容。 */
public final class RagSyncAdvice {

    @Advice.OnMethodEnter
    public static void enter(
            @Advice.This Object source,
            @Advice.Argument(0) Object request,
            @Advice.Origin("#m") String method) {
        RagBridge.before(source, request, method);
    }

    @Advice.OnMethodExit
    public static void exit(
            @Advice.This Object source,
            @Advice.Argument(0) Object request,
            @Advice.Origin("#m") String method,
            @Advice.Return Object result) {
        RagBridge.after(source, request, method, result);
    }
}
