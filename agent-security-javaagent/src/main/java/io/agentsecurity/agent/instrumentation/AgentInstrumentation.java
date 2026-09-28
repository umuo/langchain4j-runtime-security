package io.agentsecurity.agent.instrumentation;

import static net.bytebuddy.matcher.ElementMatchers.*;

import io.agentsecurity.agent.bridge.Bridge;
import io.agentsecurity.agent.bridge.MemoryBridge;
import io.agentsecurity.agent.bridge.RagBridge;
import io.agentsecurity.agent.instrumentation.advice.ErrorHandlerAdvice;
import io.agentsecurity.agent.instrumentation.advice.ExecutorArgumentAdvice;
import io.agentsecurity.agent.instrumentation.advice.ExecutorReturnAdvice;
import io.agentsecurity.agent.instrumentation.advice.ExecutorServiceReturnAdvice;
import io.agentsecurity.agent.instrumentation.advice.FutureAdvice;
import io.agentsecurity.agent.instrumentation.advice.MemoryDispatchAdvice;
import io.agentsecurity.agent.instrumentation.advice.MemoryFutureAdvice;
import io.agentsecurity.agent.instrumentation.advice.MemoryReadAdvice;
import io.agentsecurity.agent.instrumentation.advice.MemoryStoreRegistrationAdvice;
import io.agentsecurity.agent.instrumentation.advice.MemoryWriteAdvice;
import io.agentsecurity.agent.instrumentation.advice.RagConstructorAdvice;
import io.agentsecurity.agent.instrumentation.advice.RagFutureAdvice;
import io.agentsecurity.agent.instrumentation.advice.RagRegistrationAdvice;
import io.agentsecurity.agent.instrumentation.advice.RagSyncAdvice;
import io.agentsecurity.agent.instrumentation.advice.ReactiveAdvice;
import io.agentsecurity.agent.instrumentation.advice.StreamInputAdvice;
import io.agentsecurity.agent.instrumentation.advice.SyncAdvice;
import java.lang.instrument.Instrumentation;
import java.util.concurrent.CompletableFuture;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;

/** 集中注册固定 LangChain4j 版本的增强规则；实际拦截逻辑由独立 Advice 实现。 */
public final class AgentInstrumentation {

    public static void install(Instrumentation instrumentation) {
        var modelType =
                named("dev.langchain4j.model.chat.ChatModel")
                        .or(named("dev.langchain4j.model.chat.StreamingChatModel"));
        var toolType = named("dev.langchain4j.service.tool.ToolExecutor");
        var modelMethod =
                namedOneOf("chat", "doChat", "chatAsync", "doChatAsync")
                        .and(
                                takesArgument(
                                        0,
                                        named("dev.langchain4j.model.chat.request.ChatRequest")));
        var toolMethod =
                namedOneOf(
                                "execute",
                                "executeWithContext",
                                "executeAsync",
                                "executeWithErrorHandling",
                                "executeWithErrorHandlingAsync")
                        .and(
                                takesArgument(
                                        0,
                                        named("dev.langchain4j.agent.tool.ToolExecutionRequest")));
        var methods = modelMethod.or(toolMethod).and(not(isAbstract())).and(not(isNative()));
        var ragType = named(RagBridge.RETRIEVER).or(named(RagBridge.AUGMENTOR));
        var ragMethods =
                namedOneOf("retrieve", "retrieveAsync")
                        .and(takesArguments(1))
                        .and(takesArgument(0, named("dev.langchain4j.rag.query.Query")))
                        .or(
                                namedOneOf("augment", "augmentAsync")
                                        .and(takesArguments(1))
                                        .and(
                                                takesArgument(
                                                        0,
                                                        named(
                                                                "dev.langchain4j.rag.AugmentationRequest"))))
                        .and(not(isAbstract()))
                        .and(not(isNative()));
        var memoryType = named(MemoryBridge.MEMORY).or(named(MemoryBridge.STORE));
        var memoryMethods =
                namedOneOf("add", "set", "addAsync", "setAsync")
                        .and(takesArguments(1))
                        .and(
                                takesArgument(0, named("dev.langchain4j.data.message.ChatMessage"))
                                        .or(
                                                takesArgument(
                                                        0,
                                                        named(
                                                                "[Ldev.langchain4j.data.message.ChatMessage;")))
                                        .or(takesArgument(0, Iterable.class))
                                        .or(takesArgument(0, java.util.List.class)))
                        .or(namedOneOf("messages", "messagesAsync", "clear").and(takesArguments(0)))
                        .or(
                                namedOneOf(
                                                "getMessages",
                                                "getMessagesAsync",
                                                "deleteMessages",
                                                "deleteMessagesAsync")
                                        .and(takesArguments(Object.class)))
                        .or(
                                namedOneOf("updateMessages", "updateMessagesAsync")
                                        .and(takesArguments(Object.class, java.util.List.class)))
                        .and(isPublic())
                        .and(not(isAbstract()))
                        .and(not(isNative()))
                        .and(not(isStatic()));
        ThreadLocal<Boolean> failedTransform = new ThreadLocal<>();
        var transformer =
                new AgentBuilder.Default()
                        .disableClassFormatChanges()
                        .ignore(
                                nameStartsWith("net.bytebuddy.")
                                        .or(nameStartsWith("io.agentsecurity.agent."))
                                        .or(nameStartsWith("io.agentsecurity.core."))
                                        .or(nameStartsWith("io.agentsecurity.policy."))
                                        .or(nameStartsWith("io.agentsecurity.shaded."))
                                        .or(nameStartsWith("java."))
                                        .or(nameStartsWith("jdk."))
                                        .or(nameStartsWith("sun.")))
                        .with(
                                new AgentBuilder.Listener.Adapter() {

                                    @Override
                                    public void onTransformation(
                                            TypeDescription type,
                                            ClassLoader loader,
                                            JavaModule module,
                                            boolean loaded,
                                            DynamicType dynamicType) {
                                        io.agentsecurity.core.health.AgentCoverage.global()
                                                .transformed(type.getName());
                                        System.err.println(
                                                "[agent-security] instrumented=" + type.getName());
                                    }

                                    @Override
                                    public void onError(
                                            String type,
                                            ClassLoader loader,
                                            JavaModule module,
                                            boolean loaded,
                                            Throwable error) {
                                        Bridge.transformationFailed();
                                        failedTransform.set(Boolean.TRUE);
                                        System.err.println(
                                                "[agent-security] TRANSFORM_ERROR type="
                                                        + type
                                                        + " error="
                                                        + error.getClass().getName());
                                    }
                                })
                        .type(
                                modelType
                                        .or(hasSuperType(modelType))
                                        .or(toolType)
                                        .or(hasSuperType(toolType))
                                        .or(named("dev.langchain4j.service.tool.ToolService")))
                        .transform(
                                (builder, type, loader, module, domain) ->
                                        builder.visit(
                                                        Advice.to(SyncAdvice.class)
                                                                .on(
                                                                        methods.and(
                                                                                        not(
                                                                                                returns(
                                                                                                        void
                                                                                                                .class)))
                                                                                .and(
                                                                                        not(
                                                                                                returns(
                                                                                                        CompletableFuture
                                                                                                                .class)))
                                                                                .and(
                                                                                        not(
                                                                                                returns(
                                                                                                        named(
                                                                                                                "java.util.concurrent.Flow$Publisher"))))))
                                                .visit(
                                                        Advice.to(StreamInputAdvice.class)
                                                                .on(
                                                                        methods.and(
                                                                                returns(
                                                                                        void
                                                                                                .class))))
                                                .visit(
                                                        Advice.to(FutureAdvice.class)
                                                                .on(
                                                                        methods.and(
                                                                                returns(
                                                                                        CompletableFuture
                                                                                                .class))))
                                                .visit(
                                                        Advice.to(ErrorHandlerAdvice.class)
                                                                .on(
                                                                        named("toolErrorResult")
                                                                                .and(
                                                                                        takesArgument(
                                                                                                0,
                                                                                                Exception
                                                                                                        .class))))
                                                .visit(
                                                        Advice.to(ExecutorArgumentAdvice.class)
                                                                .on(
                                                                        named(
                                                                                        "executeToolsConcurrently")
                                                                                .and(
                                                                                        takesArguments(
                                                                                                java
                                                                                                        .util
                                                                                                        .concurrent
                                                                                                        .Executor
                                                                                                        .class))))
                                                .visit(
                                                        Advice.to(ReactiveAdvice.class)
                                                                .on(
                                                                        methods.and(
                                                                                returns(
                                                                                        named(
                                                                                                "java.util.concurrent.Flow$Publisher"))))))
                        .type(named("dev.langchain4j.internal.DefaultExecutorProvider"))
                        .transform(
                                (builder, type, loader, module, domain) ->
                                        builder.visit(
                                                        Advice.to(ExecutorReturnAdvice.class)
                                                                .on(
                                                                        named("getDefaultExecutor")
                                                                                .and(
                                                                                        takesArguments(
                                                                                                0))))
                                                .visit(
                                                        Advice.to(ExecutorServiceReturnAdvice.class)
                                                                .on(
                                                                        named(
                                                                                        "getDefaultExecutorService")
                                                                                .and(
                                                                                        takesArguments(
                                                                                                0)))))
                        .type(
                                ragType.or(hasSuperType(ragType))
                                        .and(not(hasSuperType(named("java.lang.reflect.Proxy")))))
                        .transform(
                                (builder, type, loader, module, domain) ->
                                        builder.visit(
                                                        Advice.to(RagSyncAdvice.class)
                                                                .on(
                                                                        ragMethods.and(
                                                                                not(
                                                                                        returns(
                                                                                                CompletableFuture
                                                                                                        .class)))))
                                                .visit(
                                                        Advice.to(RagFutureAdvice.class)
                                                                .on(
                                                                        ragMethods.and(
                                                                                returns(
                                                                                        CompletableFuture
                                                                                                .class))))
                                                .visit(
                                                        Advice.to(RagConstructorAdvice.class)
                                                                .on(
                                                                        isConstructor()
                                                                                .and(
                                                                                        isDeclaredBy(
                                                                                                named(
                                                                                                        "dev.langchain4j.rag.DefaultRetrievalAugmentor"))))))
                        .type(
                                named("dev.langchain4j.service.AiServices")
                                        .or(
                                                hasSuperType(
                                                        named(
                                                                "dev.langchain4j.service.AiServices"))))
                        .transform(
                                (builder, type, loader, module, domain) ->
                                        builder.visit(
                                                Advice.to(RagRegistrationAdvice.class)
                                                        .on(
                                                                namedOneOf(
                                                                                "contentRetriever",
                                                                                "retrievalAugmentor")
                                                                        .and(takesArguments(1))
                                                                        .and(not(isAbstract())))))
                        .type(
                                memoryType
                                        .or(hasSuperType(memoryType))
                                        .and(not(hasSuperType(named("java.lang.reflect.Proxy")))))
                        .transform(
                                (builder, type, loader, module, domain) ->
                                        builder.visit(
                                                        Advice.to(MemoryWriteAdvice.class)
                                                                .on(
                                                                        memoryMethods.and(
                                                                                returns(
                                                                                        void
                                                                                                .class))))
                                                .visit(
                                                        Advice.to(MemoryReadAdvice.class)
                                                                .on(
                                                                        memoryMethods.and(
                                                                                returns(
                                                                                        java.util
                                                                                                .List
                                                                                                .class))))
                                                .visit(
                                                        Advice.to(MemoryFutureAdvice.class)
                                                                .on(
                                                                        memoryMethods.and(
                                                                                returns(
                                                                                        CompletableFuture
                                                                                                .class)))))
                        .type(named("dev.langchain4j.service.memory.ChatMemoryService"))
                        .transform(
                                (builder, type, loader, module, domain) ->
                                        builder.visit(
                                                Advice.to(MemoryDispatchAdvice.class)
                                                        .on(
                                                                namedOneOf(
                                                                        "getOrCreateChatMemory",
                                                                        "getChatMemory"))))
                        .type(
                                named("dev.langchain4j.memory.chat.MessageWindowChatMemory$Builder")
                                        .or(
                                                named(
                                                        "dev.langchain4j.memory.chat.TokenWindowChatMemory$Builder")))
                        .transform(
                                (builder, type, loader, module, domain) ->
                                        builder.visit(
                                                Advice.to(MemoryStoreRegistrationAdvice.class)
                                                        .on(
                                                                named("chatMemoryStore")
                                                                        .and(takesArguments(1)))))
                        .makeRaw();
        instrumentation.addTransformer(
                new FailClosedTransformer(transformer, failedTransform), false);
        System.err.println(
                "[agent-security] installed; supported-langchain4j=1.20.0; mode=enforce; streaming=buffer-until-validated");
    }
}
