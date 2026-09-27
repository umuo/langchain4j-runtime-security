package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.MemoryBridge;
import io.agentsecurity.core.SecurityBlockedException;
import java.util.concurrent.CompletableFuture;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** 异步记忆边界：输入拒绝交付失败 future，完成时检查读取结果并恢复身份。 */
public final class MemoryFutureAdvice {

    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
    public static Throwable enter(
            @Advice.This Object source,
            @Advice.Origin("#m") String method,
            @Advice.AllArguments(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object[] args,
            @Advice.Local("memoryCall") MemoryBridge.Call call) {
        try {
            Object[] replacement = args.clone();
            call = MemoryBridge.before(source, method, replacement);
            args = replacement;
            return null;
        } catch (SecurityBlockedException denied) {
            return denied;
        }
    }

    @Advice.OnMethodExit
    public static void exit(
            @Advice.Enter Throwable denied,
            @Advice.Local("memoryCall") MemoryBridge.Call call,
            @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
        result =
                denied != null
                        ? CompletableFuture.failedFuture(denied)
                        : MemoryBridge.guardFuture(call, (CompletableFuture<?>) result);
    }
}
