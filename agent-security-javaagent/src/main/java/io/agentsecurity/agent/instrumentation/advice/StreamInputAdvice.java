package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.Bridge;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** 回调流入口：替换业务 handler 并检查输入，方法抛错时释放保护器占用的容量。 */
public final class StreamInputAdvice {

    @Advice.OnMethodEnter
    public static void enter(
            @Advice.Argument(0) Object request,
            @Advice.Origin("#t") String owner,
            @Advice.Origin("#m") String method,
            @Advice.AllArguments(readOnly = false, typing = Assigner.Typing.DYNAMIC)
                    Object[] arguments,
            @Advice.Local("guardedHandler") Object guardedHandler) {
        Bridge.before(request);
        // Known interface convenience methods only forward to doChat. Wrap at the provider
        // boundary.
        // Concrete chat overrides still get their own guard, including calls that bypass doChat.
        if (owner.equals("dev.langchain4j.model.chat.StreamingChatModel")
                && method.equals("chat")) {
            return;
        }
        Object[] replacement = arguments.clone();
        int index = replacement.length - 1;
        guardedHandler = Bridge.guardStream(request, replacement[index]);
        replacement[index] = guardedHandler;
        arguments = replacement;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(
            @Advice.Thrown Throwable error, @Advice.Local("guardedHandler") Object guardedHandler) {
        if (error != null && guardedHandler != null) {
            Bridge.abortStream(guardedHandler);
        }
    }
}
