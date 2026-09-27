package io.agentsecurity.agent;

import io.agentsecurity.core.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import static io.agentsecurity.core.SecurityEvent.Phase.*;

/** Fixed-version synchronous and future memory boundaries. */
public final class MemoryBridge {
    public static final String MEMORY = "dev.langchain4j.memory.ChatMemory";
    public static final String STORE = "dev.langchain4j.store.memory.chat.ChatMemoryStore";
    private static int maxMessages = 256;
    private MemoryBridge() { }
    public static void initialize(Properties properties) {
        maxMessages = Integer.parseInt(properties.getProperty("memory.max.messages", "256"));
        if (maxMessages < 1 || maxMessages > 4096) throw new IllegalArgumentException("Invalid memory.max.messages");
    }
    public record Call(Object source, String operation, ResourceRef resource, SecurityContext context, boolean read) { }

    /** Materialize and validate an entire write before delegating, including default add/set overloads. */
    public static Call before(Object source, String method, Object[] arguments) {
        Bridge.verifyBoundary(source);
        boolean store = method.startsWith("getMessages") || method.startsWith("updateMessages") || method.startsWith("deleteMessages");
        boolean read = method.startsWith("messages") || method.startsWith("getMessages");
        boolean delete = method.equals("clear") || method.startsWith("deleteMessages");
        Object id = store ? arguments[0] : invokeId(source);
        ResourceRef resource = resource(id);
        String operation = source.getClass().getName() + "#" + method;
        var call = new Call(source, operation, resource, SecurityContexts.current(), read);
        StringBuilder text = new StringBuilder();
        if (!read && !delete) {
            int index = store ? 1 : 0;
            Object input = arguments[index];
            if (input == null) throw new SecurityBlockedException("adapter-shape-error");
            if (input instanceof Iterable<?> || input.getClass().isArray()) {
                List<Object> snapshot = messages(input, text);
                if (input.getClass().isArray()) {
                    Object replacement = Array.newInstance(input.getClass().getComponentType(), snapshot.size());
                    for (int i = 0; i < snapshot.size(); i++) Array.set(replacement, i, snapshot.get(i));
                    arguments[index] = replacement;
                } else arguments[index] = snapshot;
            } else Bridge.appendMessage(text, input);
        }
        check(call, read ? MEMORY_READ_INPUT : delete ? MEMORY_DELETE : MEMORY_WRITE, text.toString());
        return call;
    }

    public static Object after(Call call, Object result) {
        if (!call.read()) return result; // Void completion legitimately returns null.
        if (result == null) throw new SecurityBlockedException("null-result");
        StringBuilder text = new StringBuilder();
        List<Object> snapshot = messages(result, text);
        check(call, MEMORY_READ_OUTPUT, text.toString());
        // Keep the mutable-list contract used by window memories, without returning the store's live list.
        return snapshot;
    }
    public static CompletableFuture<?> guardFuture(Call call, CompletableFuture<?> future) {
        return RagBridge.mapFuture(future, call.context(), result -> after(call, result));
    }
    private static void check(Call call, SecurityEvent.Phase phase, String text) {
        Bridge.check(call.source(), new SecurityEvent(UUID.randomUUID(), phase, call.operation(), text, call.context(), call.resource()));
    }
    private static List<Object> messages(Object input, StringBuilder text) {
        Iterable<?> iterable;
        if (input instanceof Iterable<?> value) iterable = value;
        else if (input instanceof Object[] array) iterable = Arrays.asList(array);
        else throw new SecurityBlockedException("adapter-shape-error");
        List<Object> result = new ArrayList<>();
        for (Object message : iterable) {
            if (result.size() == maxMessages) throw new SecurityBlockedException("memory-message-limit");
            Bridge.appendMessage(text, message); result.add(message);
        }
        return result;
    }
    private static Object invokeId(Object source) {
        try { return Class.forName(MEMORY, false, source.getClass().getClassLoader()).getMethod("id").invoke(source); }
        catch (ReflectiveOperationException | RuntimeException error) { throw new SecurityBlockedException("adapter-error"); }
    }
    static ResourceRef resource(Object id) {
        String type;
        if (id instanceof String) type = "memory:string";
        else if (id instanceof UUID) type = "memory:uuid";
        else if (id instanceof Long) type = "memory:long";
        else if (id instanceof Integer) type = "memory:int";
        else throw new SecurityBlockedException("unsupported-memory-id");
        String value = id.toString();
        if (value.length() > 1024) throw new SecurityBlockedException("memory-id-limit");
        return new ResourceRef(type, value);
    }

    /** Used at framework dispatch seams for proxy implementations as well as named memory objects. */
    public static Object wrap(Object source, String contract) {
        if (source == null) return null;
        if (Proxy.isProxyClass(source.getClass()) && Proxy.getInvocationHandler(source) instanceof Handler handler
                && handler.contract.equals(contract)) return source;
        try {
            Class<?> api = Class.forName(contract, false, source.getClass().getClassLoader());
            if (!api.isInstance(source)) throw new SecurityBlockedException("adapter-shape-error");
            return Proxy.newProxyInstance(api.getClassLoader(), new Class<?>[]{api}, new Handler(source, contract));
        } catch (ClassNotFoundException | IllegalArgumentException error) { throw new SecurityBlockedException("adapter-error"); }
    }
    private record Handler(Object source, String contract) implements InvocationHandler {
        @Override public Object invoke(Object proxy, Method method, Object[] supplied) throws Throwable {
            if (method.getDeclaringClass() == Object.class) return switch (method.getName()) {
                case "equals" -> proxy == supplied[0];
                case "hashCode" -> System.identityHashCode(proxy);
                default -> "GuardedMemoryComponent";
            };
            if (method.getName().equals("id")) return invokeId(source);
            Object[] args = supplied == null ? new Object[0] : supplied.clone();
            boolean async = CompletableFuture.class.isAssignableFrom(method.getReturnType());
            Call call;
            try { call = before(source, method.getName(), args); }
            catch (SecurityBlockedException denied) { if (async) return CompletableFuture.failedFuture(denied); throw denied; }
            Object result;
            try { result = method.invoke(source, args); }
            catch (InvocationTargetException error) { throw error.getCause(); }
            return async ? guardFuture(call, (CompletableFuture<?>) result) : after(call, result);
        }
    }
}
