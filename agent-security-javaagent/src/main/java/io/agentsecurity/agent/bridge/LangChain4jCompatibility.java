package io.agentsecurity.agent.bridge;

import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.health.AgentCoverage;
import java.lang.reflect.Modifier;

/** 补丁版本准入和关键适配契约；签名通过不代表所有调用路径已经经过回归验证。 */
final class LangChain4jCompatibility {
    private static final String PREFIX = "dev.langchain4j.";
    private static final String REQUEST = "model.chat.request.ChatRequest";
    private static final String RESPONSE = "model.chat.response.ChatResponse";
    private static final String HANDLER = "model.chat.response.StreamingChatResponseHandler";
    private static final String TOOL = "agent.tool.ToolExecutionRequest";
    private static final String MESSAGE = "data.message.ChatMessage";
    private static final String FUTURE = "java.util.concurrent.CompletableFuture";

    private LangChain4jCompatibility() {}

    static boolean accepts(String version) {
        if (version == null) {
            return false;
        }
        for (String baseline : AgentCoverage.VERIFIED_LANGCHAIN4J) {
            String series = baseline.substring(0, baseline.lastIndexOf('.') + 1);
            if (version.startsWith(series)
                    && version.substring(series.length()).matches("0|[1-9][0-9]*")) {
                return true;
            }
        }
        return false;
    }

    static void verifyApi(ClassLoader loader) {
        try {
            method(loader, REQUEST, "messages", "java.util.List");
            method(loader, RESPONSE, "aiMessage", "data.message.AiMessage");
            method(loader, TOOL, "name", "java.lang.String");
            method(loader, TOOL, "arguments", "java.lang.String");
            for (String name : new String[] {"chat", "doChat"}) {
                method(loader, "model.chat.ChatModel", name, RESPONSE, REQUEST);
                method(loader, "model.chat.ChatModel", name + "Async", FUTURE, REQUEST);
                method(loader, "model.chat.StreamingChatModel", name, "void", REQUEST, HANDLER);
                method(
                        loader,
                        "model.chat.StreamingChatModel",
                        name,
                        "java.util.concurrent.Flow$Publisher",
                        REQUEST);
            }
            method(loader, HANDLER, "onPartialResponse", "void", "java.lang.String");
            method(loader, HANDLER, "onCompleteResponse", "void", RESPONSE);
            method(loader, HANDLER, "onError", "void", "java.lang.Throwable");
            for (String owner :
                    new String[] {
                        "data.message.SystemMessage",
                        "data.message.TextContent",
                        "data.message.AiMessage"
                    }) {
                method(loader, owner, "text", "java.lang.String");
            }
            method(loader, "data.message.AiMessage", "thinking", "java.lang.String");
            method(loader, "data.message.AiMessage", "toolExecutionRequests", "java.util.List");
            method(loader, "data.message.UserMessage", "contents", "java.util.List");
            method(loader, "data.message.ToolExecutionResultMessage", "contents", "java.util.List");
            method(loader, MemoryBridge.MEMORY, "id", "java.lang.Object");
            method(loader, MemoryBridge.MEMORY, "add", "void", MESSAGE);
            method(loader, MemoryBridge.MEMORY, "messages", "java.util.List");
            method(loader, MemoryBridge.MEMORY, "clear", "void");
            method(loader, MemoryBridge.STORE, "getMessages", "java.util.List", "java.lang.Object");
            method(
                    loader,
                    MemoryBridge.STORE,
                    "updateMessages",
                    "void",
                    "java.lang.Object",
                    "java.util.List");
            method(loader, MemoryBridge.STORE, "deleteMessages", "void", "java.lang.Object");
            method(loader, RagBridge.RETRIEVER, "retrieve", "java.util.List", "rag.query.Query");
            method(loader, RagBridge.RETRIEVER, "retrieveAsync", FUTURE, "rag.query.Query");
            method(
                    loader,
                    RagBridge.AUGMENTOR,
                    "augment",
                    "rag.AugmentationResult",
                    "rag.AugmentationRequest");
            method(loader, RagBridge.AUGMENTOR, "augmentAsync", FUTURE, "rag.AugmentationRequest");
            // AI Services is an optional artifact; core-only applications do not need it.
            try {
                Class.forName(PREFIX + "service.tool.ToolExecutor", false, loader);
            } catch (ClassNotFoundException absent) {
                return;
            }
            method(
                    loader,
                    "service.tool.ToolExecutor",
                    "execute",
                    "java.lang.String",
                    TOOL,
                    "java.lang.Object");
            method(
                    loader,
                    "service.tool.ToolExecutor",
                    "executeWithContext",
                    "service.tool.ToolExecutionResult",
                    TOOL,
                    "invocation.InvocationContext");
            method(
                    loader,
                    "service.tool.ToolExecutor",
                    "executeAsync",
                    FUTURE,
                    TOOL,
                    "invocation.InvocationContext");
            method(loader, "service.tool.ToolExecutionResult", "resultText", "java.lang.String");
        } catch (ReflectiveOperationException | LinkageError | RuntimeException failure) {
            // Do not expose dependency exception messages or business data.
            throw new SecurityBlockedException("incompatible-langchain4j-api");
        }
    }

    private static void method(
            ClassLoader loader, String owner, String name, String result, String... parameters)
            throws ReflectiveOperationException {
        Class<?>[] arguments = new Class<?>[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            arguments[i] = type(loader, parameters[i]);
        }
        var method = type(loader, owner).getMethod(name, arguments);
        if (Modifier.isStatic(method.getModifiers())
                || method.getReturnType() != type(loader, result)) {
            throw new NoSuchMethodException();
        }
    }

    private static Class<?> type(ClassLoader loader, String name) throws ClassNotFoundException {
        if (name.equals("void")) {
            return void.class;
        }
        return Class.forName(
                name.startsWith("java.") || name.startsWith(PREFIX) ? name : PREFIX + name,
                false,
                loader);
    }
}
