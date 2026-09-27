package io.agentsecurity.agent.bridge;

import static io.agentsecurity.core.SecurityEvent.Phase.*;

import io.agentsecurity.agent.stream.ContextPublisher;
import io.agentsecurity.agent.stream.GuardedPublisher;
import io.agentsecurity.agent.stream.GuardedStream;
import io.agentsecurity.core.Detector;
import io.agentsecurity.core.PolicyEngine;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import io.agentsecurity.core.SecurityEvent;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.WeakHashMap;
import java.util.concurrent.CompletableFuture;

/** 模型与工具调用的运行时桥接层。通过反射适配业务类，避免 Agent 与应用依赖发生类加载冲突。 */
public final class Bridge {

    private static volatile PolicyEngine engine;

    private static final java.util.Map<ClassLoader, Boolean> checkedLoaders =
            Collections.synchronizedMap(new WeakHashMap<>());

    private static int maxTextChars;

    private static volatile ClassValue<PolicyEngine> engines = newEngines();

    private static ClassValue<PolicyEngine> newEngines() {
        return new ClassValue<>() {

            @Override
            protected PolicyEngine computeValue(Class<?> requestClass) {
                try {
                    var plugins =
                            engine.loadDetectors(
                                    () ->
                                            java.util.ServiceLoader.load(
                                                            Detector.class,
                                                            requestClass.getClassLoader())
                                                    .stream()
                                                    .map(java.util.ServiceLoader.Provider::get)
                                                    .toList());
                    return engine.withAdditionalDetectors(plugins);
                } catch (SecurityBlockedException denied) {
                    throw denied;
                } catch (java.util.ServiceConfigurationError | RuntimeException e) {
                    throw new SecurityBlockedException("detector-load-error");
                }
            }
        };
    }

    private static volatile boolean transformationFailed;

    private Bridge() {}

    public static void initialize(PolicyEngine policy, int maxChars) {
        engine = policy;
        maxTextChars = maxChars;
        engines = newEngines();
    }

    public static void transformationFailed() {
        transformationFailed = true;
    }

    public static Object guardStream(Object request, Object handler) {
        return GuardedStream.wrap(request, handler);
    }

    public static void abortStream(Object handler) {
        GuardedStream.abort(handler);
    }

    public static java.util.concurrent.Flow.Publisher<?> guardPublisher(
            Object request, java.util.concurrent.Flow.Publisher<?> source) {
        if (source == null) {
            return failedPublisher(new SecurityBlockedException("null-result"));
        }
        SecurityContext context = SecurityContexts.current();
        return new ContextPublisher(
                new GuardedPublisher(request, new ContextPublisher(source, context)), context);
    }

    public static java.util.concurrent.Flow.Publisher<?> contextPublisher(
            java.util.concurrent.Flow.Publisher<?> source, SecurityContext context) {
        return source == null
                ? failedPublisher(new SecurityBlockedException("null-result"))
                : new ContextPublisher(source, context);
    }

    public static java.util.concurrent.Flow.Publisher<?> failedPublisher(Throwable error) {
        return subscriber -> {
            java.util.Objects.requireNonNull(subscriber);
            var cancelled = new java.util.concurrent.atomic.AtomicBoolean();
            try {
                subscriber.onSubscribe(
                        new java.util.concurrent.Flow.Subscription() {

                            @Override
                            public void request(long count) {}

                            @Override
                            public void cancel() {
                                cancelled.set(true);
                            }
                        });
                if (!cancelled.get()) {
                    subscriber.onError(error);
                }
            } catch (Throwable consumerFailure) {
                /* Do not issue another signal after a subscriber throws. */
            }
        };
    }

    public static void checkStreamText(Object request, String text) {
        engines.get(request.getClass()).check(new SecurityEvent(MODEL_OUTPUT, "stream", text));
    }

    public static void before(Object request) {
        verifyBoundary(request);
        if (isTool(request)) {
            engines.get(request.getClass())
                    .check(
                            new SecurityEvent(
                                    TOOL_INPUT,
                                    string(call(request, "name")),
                                    string(call(request, "arguments"))));
        } else {
            StringBuilder text = new StringBuilder();
            for (Object message : list(call(request, "messages"))) {
                appendMessage(text, message);
            }
            engines.get(request.getClass())
                    .check(new SecurityEvent(MODEL_INPUT, "chat", text.toString()));
        }
    }

    static void verifyBoundary(Object request) {
        if (transformationFailed) {
            throw new SecurityBlockedException("instrumentation-error");
        }
        if (request == null) {
            throw new SecurityBlockedException("adapter-shape-error");
        }
        verifyVersion(request.getClass().getClassLoader());
    }

    static void check(Object request, SecurityEvent event) {
        engines.get(request.getClass()).check(event);
    }

    public static void after(Object request, Object result) {
        if (result == null) {
            throw new SecurityBlockedException("null-result");
        }
        if (isTool(request)) {
            String text = result instanceof String s ? s : string(call(result, "resultText"));
            engines.get(request.getClass())
                    .check(new SecurityEvent(TOOL_OUTPUT, string(call(request, "name")), text));
        } else {
            StringBuilder text = new StringBuilder();
            appendMessage(text, call(result, "aiMessage"));
            engines.get(request.getClass())
                    .check(new SecurityEvent(MODEL_OUTPUT, "chat", text.toString()));
        }
    }

    public static CompletableFuture<?> guardFuture(Object request, CompletableFuture<?> source) {
        return guardFuture(request, source, SecurityContexts.current());
    }

    public static CompletableFuture<?> guardFuture(
            Object request, CompletableFuture<?> source, SecurityContext context) {
        CompletableFuture<Object> guarded = new CompletableFuture<>();
        source.whenComplete(
                (value, error) -> {
                    try (var scope = SecurityContexts.restore(context)) {
                        if (error != null) {
                            guarded.completeExceptionally(error);
                        } else {
                            try {
                                after(request, value);
                                guarded.complete(value);
                            } catch (Throwable denied) {
                                guarded.completeExceptionally(denied);
                            }
                        }
                    }
                });
        guarded.whenComplete(
                (value, error) -> {
                    try (var scope = SecurityContexts.restore(context)) {
                        if (guarded.isCancelled()) {
                            source.cancel(true);
                        }
                    }
                });
        return guarded;
    }

    private static boolean isTool(Object request) {
        return request.getClass()
                .getName()
                .equals("dev.langchain4j.agent.tool.ToolExecutionRequest");
    }

    static void appendMessage(StringBuilder text, Object message) {
        if (message == null) {
            throw new SecurityBlockedException("adapter-shape-error");
        }
        String kind = message.getClass().getSimpleName();
        switch (kind) {
            case "UserMessage", "ToolExecutionResultMessage" -> {
                for (Object content : list(call(message, "contents"))) {
                    if (!content.getClass().getSimpleName().equals("TextContent")) {
                        throw new SecurityBlockedException("unsupported-content");
                    }
                    append(text, string(call(content, "text")));
                }
            }
            case "SystemMessage" -> append(text, string(call(message, "text")));
            case "AiMessage" -> {
                append(text, string(call(message, "text")));
                append(text, string(call(message, "thinking")));
                Object calls = call(message, "toolExecutionRequests");
                if (calls != null) {
                    for (Object tool : list(calls)) {
                        append(text, string(call(tool, "name")));
                        append(text, string(call(tool, "arguments")));
                    }
                }
            }
            default -> throw new SecurityBlockedException("unsupported-message");
        }
    }

    static void append(StringBuilder target, String text) {
        if (text.isEmpty()) {
            return;
        }
        if (text.length() > maxTextChars - target.length() - 1) {
            throw new SecurityBlockedException("text-limit");
        }
        target.append(text).append('\n');
    }

    private static List<?> list(Object value) {
        if (value instanceof List<?> list) {
            return list;
        }
        throw new SecurityBlockedException("adapter-shape-error");
    }

    private static String string(Object value) {
        return value == null ? "" : value.toString();
    }

    public static Object call(Object target, String method) {
        try {
            return target.getClass().getMethod(method).invoke(target);
        } catch (ReflectiveOperationException | RuntimeException error) {
            // Do not include payloads or reflection exception messages in audit/errors.
            throw new SecurityBlockedException("adapter-error");
        }
    }

    private static void verifyVersion(ClassLoader loader) {
        if (loader == null) {
            throw new SecurityBlockedException("unsupported-classloader");
        }
        if (checkedLoaders.containsKey(loader)) {
            return;
        }
        try (InputStream stream =
                loader.getResourceAsStream(
                        "META-INF/maven/dev.langchain4j/langchain4j-core/pom.properties")) {
            if (stream == null) {
                throw new SecurityBlockedException("missing-version-metadata");
            }
            Properties p = new Properties();
            p.load(stream);
            if (!"1.20.0".equals(p.getProperty("version"))) {
                throw new SecurityBlockedException("unsupported-langchain4j-version");
            }
            checkedLoaders.put(loader, Boolean.TRUE);
        } catch (java.io.IOException e) {
            throw new SecurityBlockedException("version-check-error");
        }
    }
}
