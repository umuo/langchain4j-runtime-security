package io.agentsecurity.agent.bridge;

import static io.agentsecurity.core.SecurityEvent.Phase.*;

import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import io.agentsecurity.core.SecurityEvent;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

/** 检索与增强流程的边界适配。分别检查输入和整批结果，并为异步完成恢复原请求身份。 */
public final class RagBridge {

    public static final String RETRIEVER = "dev.langchain4j.rag.content.retriever.ContentRetriever";

    public static final String AUGMENTOR = "dev.langchain4j.rag.RetrievalAugmentor";

    private static volatile int maxContents = 256;

    private static volatile int maxMetadataEntries = 64;

    private RagBridge() {}

    public static void initialize(Properties properties) {
        maxContents = limit(properties, "rag.max.contents", 256, 4096);
        maxMetadataEntries = limit(properties, "rag.max.metadata.entries", 64, 1024);
    }

    private static int limit(Properties properties, String key, int fallback, int ceiling) {
        int value = Integer.parseInt(properties.getProperty(key, Integer.toString(fallback)));
        if (value < 1 || value > ceiling) {
            throw new IllegalArgumentException("Invalid " + key);
        }
        return value;
    }

    public static void before(Object source, Object request, String method) {
        Bridge.verifyBoundary(request);
        StringBuilder text = new StringBuilder();
        boolean retrieve = method.startsWith("retrieve");
        if (retrieve) {
            Bridge.append(text, requiredString(Bridge.call(request, "text")));
        } else {
            Bridge.appendMessage(text, Bridge.call(request, "chatMessage"));
        }
        Object metadata = Bridge.call(request, "metadata");
        if (metadata != null) {
            Bridge.appendMessage(text, Bridge.call(metadata, "chatMessage"));
            Object system = Bridge.call(metadata, "systemMessage");
            if (system != null) {
                Bridge.appendMessage(text, system);
            }
            Object memory = Bridge.call(metadata, "chatMemory");
            if (memory != null) {
                for (Object message : boundedCollection(memory, maxContents)) {
                    Bridge.appendMessage(text, message);
                }
            }
        }
        Bridge.check(
                request,
                new SecurityEvent(
                        retrieve ? RETRIEVAL_INPUT : AUGMENTATION_INPUT,
                        sourceName(source),
                        text.toString()));
    }

    public static void after(Object source, Object request, String method, Object result) {
        if (result == null) {
            throw new SecurityBlockedException("null-result");
        }
        StringBuilder text = new StringBuilder();
        boolean retrieve = method.startsWith("retrieve");
        Object contents;
        if (retrieve) {
            contents = result;
        } else {
            Bridge.appendMessage(text, Bridge.call(result, "chatMessage"));
            contents = Bridge.call(result, "contents");
        }
        // AugmentationResult may omit source contents; its message is still checked.
        if (contents != null) {
            for (Object content : boundedCollection(contents, maxContents)) {
                if (content == null) {
                    throw new SecurityBlockedException("adapter-shape-error");
                }
                Object segment =
                        interfaceCall(
                                content, "dev.langchain4j.rag.content.Content", "textSegment");
                if (segment == null) {
                    throw new SecurityBlockedException("adapter-shape-error");
                }
                Bridge.append(text, requiredString(Bridge.call(segment, "text")));
                Object metadata = Bridge.call(Bridge.call(segment, "metadata"), "toMap");
                if (!(metadata instanceof Map<?, ?> map)) {
                    throw new SecurityBlockedException("adapter-shape-error");
                }
                if (map.size() > maxMetadataEntries) {
                    throw new SecurityBlockedException("rag-content-limit");
                }
                for (var entry : map.entrySet()) {
                    Bridge.append(text, requiredString(entry.getKey()));
                    Object value = entry.getValue();
                    if (!(value instanceof String
                            || value instanceof UUID
                            || value instanceof Integer
                            || value instanceof Long
                            || value instanceof Float
                            || value instanceof Double)) {
                        throw new SecurityBlockedException("unsupported-rag-metadata");
                    }
                    Bridge.append(text, value.toString());
                }
            }
        }
        Bridge.check(
                request,
                new SecurityEvent(
                        retrieve ? RETRIEVAL_OUTPUT : AUGMENTATION_OUTPUT,
                        sourceName(source),
                        text.toString()));
    }

    public static CompletableFuture<?> guardFuture(
            Object source,
            Object request,
            String method,
            CompletableFuture<?> future,
            SecurityContext context) {
        return mapFuture(
                future,
                context,
                result -> {
                    after(source, request, method, result);
                    return result;
                });
    }

    static CompletableFuture<?> mapFuture(
            CompletableFuture<?> future, SecurityContext context, Function<Object, Object> mapper) {
        if (future == null) {
            return CompletableFuture.failedFuture(new SecurityBlockedException("null-result"));
        }
        var result = new CompletableFuture<Object>();
        future.whenComplete(
                (value, error) -> {
                    try (var scope = SecurityContexts.restore(context)) {
                        if (error != null) {
                            result.completeExceptionally(error);
                        } else {
                            try {
                                result.complete(mapper.apply(value));
                            } catch (Throwable failure) {
                                result.completeExceptionally(failure);
                            }
                        }
                    }
                });
        result.whenComplete(
                (value, error) -> {
                    try (var scope = SecurityContexts.restore(context)) {
                        if (result.isCancelled()) {
                            future.cancel(true);
                        }
                    }
                });
        return result;
    }

    /**
     * Wrap dispatch seams as well as named implementations, so framework-dispatched lambdas are
     * checked.
     */
    public static Object wrap(Object source, String contract, String kind) {
        if (source == null) {
            return null;
        }
        if (Proxy.isProxyClass(source.getClass())
                && Proxy.getInvocationHandler(source) instanceof Handler handler
                && handler.contract.equals(contract)) {
            return source;
        }
        try {
            Class<?> api = Class.forName(contract, false, source.getClass().getClassLoader());
            if (!api.isInstance(source)) {
                throw new SecurityBlockedException("adapter-shape-error");
            }
            return Proxy.newProxyInstance(
                    api.getClassLoader(),
                    new Class<?>[] {api},
                    new Handler(source, contract, kind));
        } catch (ClassNotFoundException | IllegalArgumentException error) {
            throw new SecurityBlockedException("adapter-error");
        }
    }

    private record Handler(Object source, String contract, String kind)
            implements InvocationHandler {

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                    case "equals" -> proxy == args[0];
                    case "hashCode" -> System.identityHashCode(proxy);
                    default -> "GuardedRagComponent";
                };
            }
            String name = method.getName();
            boolean boundary =
                    (kind.equals("retrieve")
                                    && (name.equals("retrieve") || name.equals("retrieveAsync")))
                            || (kind.equals("augment")
                                    && (name.equals("augment") || name.equals("augmentAsync")));
            boolean async = CompletableFuture.class.isAssignableFrom(method.getReturnType());
            SecurityContext context = SecurityContexts.current();
            if (boundary) {
                try {
                    before(source, args[0], name);
                } catch (SecurityBlockedException denied) {
                    if (async) {
                        return CompletableFuture.failedFuture(denied);
                    }
                    throw denied;
                }
            }
            Object result;
            try {
                result = method.invoke(source, args);
            } catch (InvocationTargetException error) {
                throw error.getCause();
            }
            Function<Object, Object> mapper =
                    value -> {
                        if (boundary) {
                            after(source, args[0], name, value);
                        }
                        if (kind.equals("route")
                                && (name.equals("route") || name.equals("routeAsync"))) {
                            List<Object> guarded = new ArrayList<>();
                            for (Object retriever : boundedCollection(value, maxContents)) {
                                if (retriever == null) {
                                    throw new SecurityBlockedException("adapter-shape-error");
                                }
                                guarded.add(wrap(retriever, RETRIEVER, "retrieve"));
                            }
                            return List.copyOf(guarded);
                        }
                        return value;
                    };
            return async
                    ? mapFuture((CompletableFuture<?>) result, context, mapper)
                    : mapper.apply(result);
        }
    }

    private static Collection<?> boundedCollection(Object value, int max) {
        if (!(value instanceof Collection<?> collection)) {
            throw new SecurityBlockedException("adapter-shape-error");
        }
        if (collection.size() > max) {
            throw new SecurityBlockedException("rag-content-limit");
        }
        return collection;
    }

    private static String requiredString(Object value) {
        if (value instanceof String text) {
            return text;
        }
        throw new SecurityBlockedException("adapter-shape-error");
    }

    private static Object interfaceCall(Object target, String contract, String method) {
        try {
            return Class.forName(contract, false, target.getClass().getClassLoader())
                    .getMethod(method)
                    .invoke(target);
        } catch (ReflectiveOperationException | RuntimeException error) {
            throw new SecurityBlockedException("adapter-error");
        }
    }

    private static String sourceName(Object source) {
        Class<?> type = source.getClass();
        // Hidden lambda names carry per-process suffixes, so report the declaring host instead.
        return type.isHidden() ? "lambda:" + type.getNestHost().getName() : type.getName();
    }
}
