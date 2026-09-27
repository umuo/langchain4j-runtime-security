package io.agentsecurity.agent.stream;

import io.agentsecurity.agent.bridge.Bridge;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;

/** 缓冲回调式流的正文、思考内容和工具调用；最终响应及实际片段均检查通过后才向业务释放。 */
public final class GuardedStream implements InvocationHandler {

    private static StreamLimits limits;

    public static void initialize(StreamLimits config) {
        limits = config;
        StreamRuntime.initialize(config);
    }

    public static Object wrap(Object request, Object handler) {
        if (handler == null) {
            throw new SecurityBlockedException("missing-stream-handler");
        }
        if (Proxy.isProxyClass(handler.getClass())
                && Proxy.getInvocationHandler(handler) instanceof GuardedStream) {
            return handler;
        }
        if (!StreamRuntime.acquire()) {
            throw new SecurityBlockedException("stream-capacity");
        }
        boolean transferred = false;
        try {
            Class<?> contract =
                    Class.forName(
                            "dev.langchain4j.model.chat.response.StreamingChatResponseHandler",
                            false,
                            handler.getClass().getClassLoader());
            GuardedStream guard = new GuardedStream(request, handler, contract);
            Object proxy =
                    Proxy.newProxyInstance(
                            contract.getClassLoader(), new Class<?>[] {contract}, guard);
            guard.deadline = StreamRuntime.schedule(guard::timeout);
            transferred = true;
            return proxy;
        } catch (ReflectiveOperationException | IllegalArgumentException e) {
            throw new SecurityBlockedException("stream-adapter-error");
        } finally {
            if (!transferred) {
                StreamRuntime.release();
            }
        }
    }

    public static void abort(Object handler) {
        if (Proxy.isProxyClass(handler.getClass())
                && Proxy.getInvocationHandler(handler) instanceof GuardedStream guard) {
            synchronized (guard) {
                if (guard.terminal) {
                    return;
                }
                guard.finishLocked();
            }
            try {
                guard.cancel();
            } finally {
                StreamRuntime.release();
            }
        }
    }

    private final Object request;

    private final SecurityContext context = SecurityContexts.current();

    private final Object downstream;

    private final Class<?> contract;

    private final List<Callback> pending = new ArrayList<>();

    private final Map<String, StringBuilder> channels = new HashMap<>();

    private final List<Object> completeTools = new ArrayList<>();

    private int chars;

    private boolean terminal;

    private Object cancelHandle;

    private volatile ScheduledFuture<?> deadline;

    private GuardedStream(Object request, Object downstream, Class<?> contract) {
        this.request = request;
        this.downstream = downstream;
        this.contract = contract;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] supplied) throws Throwable {
        try (var scope = SecurityContexts.restore(context)) {
            return invokeInContext(proxy, method, supplied);
        }
    }

    private Object invokeInContext(Object proxy, Method method, Object[] supplied)
            throws Throwable {
        if (method.getDeclaringClass() == Object.class) {
            return switch (method.getName()) {
                case "toString" -> "AgentSecurityStreamingHandler";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == supplied[0];
                default -> throw new UnsupportedOperationException();
            };
        }
        Object[] args = supplied == null ? new Object[0] : supplied.clone();
        List<Callback> release = null;
        Throwable failure = null;
        synchronized (this) {
            if (terminal) {
                return null;
            }
            try {
                if (method.getName().startsWith("onPartial")
                        && args.length > 1
                        && args[1] != null) {
                    cancelHandle = Bridge.call(args[1], "streamingHandle");
                }
                switch (method.getName()) {
                    case "onError" ->
                            failure =
                                    args[0] instanceof Throwable throwable
                                            ? throwable
                                            : new SecurityBlockedException("invalid-stream-error");
                    case "onCompleteResponse" -> {
                        // The final response need not include all partial bytes (buggy/custom
                        // providers).
                        for (StringBuilder channel : channels.values()) {
                            Bridge.checkStreamText(request, channel.toString());
                        }
                        for (Object tool : completeTools) {
                            Bridge.before(tool);
                        }
                        Bridge.after(request, args[0]);
                        release = new ArrayList<>(pending);
                        release.add(new Callback(method, args));
                    }
                    case "onPartialResponse" -> buffer(method, args, "text", text(args[0]));
                    case "onPartialThinking" -> buffer(method, args, "thinking", text(args[0]));
                    case "onPartialToolCall" -> {
                        Object part = args[0];
                        metadata(Bridge.call(part, "name"));
                        metadata(Bridge.call(part, "id"));
                        buffer(
                                method,
                                args,
                                "tool-" + Bridge.call(part, "index"),
                                String.valueOf(Bridge.call(part, "partialArguments")));
                    }
                    case "onCompleteToolCall" -> {
                        Object tool = Bridge.call(args[0], "toolExecutionRequest");
                        String name = String.valueOf(Bridge.call(tool, "name"));
                        String arguments = String.valueOf(Bridge.call(tool, "arguments"));
                        metadata(name);
                        metadata(Bridge.call(tool, "id"));
                        buffer(method, args, "complete-tool-" + completeTools.size(), arguments);
                        completeTools.add(tool);
                    }
                    case "onUnmappedRawEvent" -> {
                        String control =
                                RawStreamControl.inspect(
                                        request, args[0], limits.maxChars() - chars);
                        buffer(method, args, "control-" + pending.size(), control);
                    }
                    // Unknown raw events may carry unchecked content. Never forward them
                    // uninspected.
                    default -> throw new SecurityBlockedException("unsupported-stream-event");
                }
            } catch (SecurityBlockedException denied) {
                failure = denied;
            }
            if (failure != null || release != null) {
                finishLocked();
            }
        }
        if (failure != null) {
            try {
                cancel();
                notifyError(failure);
            } finally {
                StreamRuntime.release();
            }
        } else if (release != null) {
            try {
                // Downstream callback exceptions propagate; never deliver a second terminal
                // callback.
                for (Callback callback : release) {
                    callback.deliver(downstream);
                }
            } finally {
                StreamRuntime.release();
            }
        }
        return null;
    }

    private void buffer(Method method, Object[] args, String channel, String text) {
        if (pending.size() >= limits.maxEvents() || text.length() > limits.maxChars() - chars) {
            throw new SecurityBlockedException("stream-buffer-limit");
        }
        chars += text.length();
        channels.computeIfAbsent(channel, ignored -> new StringBuilder()).append(text);
        pending.add(new Callback(method, args));
    }

    private void metadata(Object value) {
        if (value == null) {
            return;
        }
        String text = value.toString();
        if (text.length() > limits.maxChars() - chars) {
            throw new SecurityBlockedException("stream-buffer-limit");
        }
        chars += text.length();
        Bridge.checkStreamText(request, text);
    }

    private static String text(Object value) {
        return value instanceof String string ? string : String.valueOf(Bridge.call(value, "text"));
    }

    private void finishLocked() {
        terminal = true;
        if (deadline != null) {
            deadline.cancel(false);
        }
        pending.clear();
        channels.clear();
        completeTools.clear();
    }

    private void timeout() {
        synchronized (this) {
            if (terminal) {
                return;
            }
            finishLocked();
        }
        StreamRuntime.notifyLater(
                () -> {
                    try (var scope = SecurityContexts.restore(context)) {
                        cancel();
                        notifyError(new SecurityBlockedException("stream-timeout"));
                    } catch (Throwable ignored) {
                        /* Consumer failure must not break other deadlines. */
                    } finally {
                        StreamRuntime.release();
                    }
                });
    }

    private void cancel() {
        if (cancelHandle == null) {
            return;
        }
        try {
            // Invoke the public interface: provider implementations can be non-public.
            Class<?> handle =
                    Class.forName(
                            "dev.langchain4j.model.chat.response.StreamingHandle",
                            false,
                            cancelHandle.getClass().getClassLoader());
            handle.getMethod("cancel").invoke(cancelHandle);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // Dropping future callbacks still prevents egress; cancellation is best effort.
        }
    }

    private void notifyError(Throwable failure) throws Throwable {
        new Callback(contract.getMethod("onError", Throwable.class), new Object[] {failure})
                .deliver(downstream);
    }

    private record Callback(Method method, Object[] args) {

        void deliver(Object downstream) throws Throwable {
            try {
                method.invoke(downstream, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        }
    }
}
