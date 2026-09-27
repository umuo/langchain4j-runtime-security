package io.agentsecurity.agent;

import io.agentsecurity.core.*;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import static net.bytebuddy.matcher.ElementMatchers.*;

public final class SecurityAgent {
    public static void premain(String arguments, Instrumentation instrumentation) throws Exception {
        for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
            if (loaded.getName().startsWith("dev.langchain4j."))
                throw new IllegalStateException("LangChain4j already loaded; put the security agent before agents that load it");
        }
        if (arguments == null || arguments.isBlank())
            throw new IllegalArgumentException("Use -javaagent:agent.jar=/absolute/path/policy.properties");
        Properties properties = new Properties();
        try (var reader = Files.newBufferedReader(Path.of(arguments), StandardCharsets.UTF_8)) { properties.load(reader); }
        StreamLimits streamLimits = StreamLimits.from(properties);
        RagBridge.initialize(properties);
        MemoryBridge.initialize(properties);
        Properties localProperties = new Properties();
        var streamKeys = java.util.Set.of("stream.max.chars", "stream.max.events", "stream.max.active", "stream.timeout.millis",
                "detector.timeout.millis", "detector.max.concurrent", "audit.path", "audit.max.bytes", "audit.backups",
                "audit.force", "audit.timeout.millis", "audit.queue.capacity", "policy.version", "tool.policy.path", "context.required",
                "rag.max.contents", "rag.max.metadata.entries", "memory.max.messages");
        for (String key : properties.stringPropertyNames())
            if (!streamKeys.contains(key)) localProperties.setProperty(key, properties.getProperty(key));
        var detectors = new ArrayList<Detector>();
        String requireContext = properties.getProperty("context.required", "false");
        if (!requireContext.equals("true") && !requireContext.equals("false")) throw new IllegalArgumentException("Invalid context.required");
        if (requireContext.equals("true")) detectors.add(new RequiredContextPolicy());
        LocalPolicy localPolicy = new LocalPolicy(localProperties);
        detectors.add(localPolicy);
        if (properties.containsKey("tool.policy.path")) {
            String file = properties.getProperty("tool.policy.path");
            if (file.isBlank()) throw new IllegalArgumentException("Empty tool.policy.path");
            Path path = Path.of(arguments).toAbsolutePath().getParent().resolve(file).normalize();
            detectors.add(io.agentsecurity.policy.ToolPolicy.fromPath(path, localPolicy));
        }
        var limits = new DetectionLimits(java.time.Duration.ofMillis(Long.parseLong(properties.getProperty("detector.timeout.millis", "500"))),
                Integer.parseInt(properties.getProperty("detector.max.concurrent", "4")));
        String policyVersion = properties.getProperty("policy.version", "unversioned");
        if (!policyVersion.matches("[a-zA-Z0-9_.-]{1,80}")) throw new IllegalArgumentException("Invalid policy.version");
        String forceValue = properties.getProperty("audit.force", "true");
        if (!forceValue.equals("true") && !forceValue.equals("false")) throw new IllegalArgumentException("Invalid audit.force");
        if (!properties.containsKey("audit.path") && java.util.stream.Stream.of("audit.force", "audit.max.bytes", "audit.backups")
                .anyMatch(properties::containsKey)) throw new IllegalArgumentException("File audit settings require audit.path");
        java.util.function.BiConsumer<SecurityEvent, Decision> auditTarget = (event, decision) -> {
            // Deliberately omit prompt, tool arguments, results and arbitrary user-supplied names.
            synchronized (System.err) {
                System.err.printf("[agent-security] event=%s run=%s decision=%s phase=%s rule=%s policy=%s%n",
                        event.id(), event.context() == null ? "none" : event.context().runId(), decision.allowed() ? "ALLOW" : "DENY", event.phase(), decision.ruleId(), policyVersion);
                if (System.err.checkError()) throw new IllegalStateException("Audit stderr failed");
            }
        };
        if (properties.containsKey("audit.path")) {
            String auditPath = properties.getProperty("audit.path");
            if (auditPath.isBlank()) throw new IllegalArgumentException("Empty audit.path");
            auditTarget = new FileAuditSink(Path.of(auditPath),
                    Long.parseLong(properties.getProperty("audit.max.bytes", "10485760")),
                    Integer.parseInt(properties.getProperty("audit.backups", "5")), Boolean.parseBoolean(forceValue), policyVersion);
        }
        var audit = new BoundedAuditSink(auditTarget,
                java.time.Duration.ofMillis(Long.parseLong(properties.getProperty("audit.timeout.millis", "1000"))),
                Integer.parseInt(properties.getProperty("audit.queue.capacity", "128")));
        PolicyEngine policyEngine = new PolicyEngine(detectors, audit, limits);
        Bridge.initialize(policyEngine, Integer.parseInt(localProperties.getProperty("max.text.chars", "100000")));
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            policyEngine.close();
            audit.close();
        }, "agent-security-shutdown"));
        GuardedStream.initialize(streamLimits);

        var modelType = named("dev.langchain4j.model.chat.ChatModel")
                .or(named("dev.langchain4j.model.chat.StreamingChatModel"));
        var toolType = named("dev.langchain4j.service.tool.ToolExecutor");
        var modelMethod = namedOneOf("chat", "doChat", "chatAsync", "doChatAsync")
                .and(takesArgument(0, named("dev.langchain4j.model.chat.request.ChatRequest")));
        var toolMethod = namedOneOf("execute", "executeWithContext", "executeAsync", "executeWithErrorHandling", "executeWithErrorHandlingAsync")
                .and(takesArgument(0, named("dev.langchain4j.agent.tool.ToolExecutionRequest")));
        var methods = modelMethod.or(toolMethod).and(not(isAbstract())).and(not(isNative()));
        var ragType = named(RagBridge.RETRIEVER).or(named(RagBridge.AUGMENTOR));
        var ragMethods = namedOneOf("retrieve", "retrieveAsync").and(takesArguments(1))
                .and(takesArgument(0, named("dev.langchain4j.rag.query.Query")))
                .or(namedOneOf("augment", "augmentAsync").and(takesArguments(1))
                        .and(takesArgument(0, named("dev.langchain4j.rag.AugmentationRequest"))))
                .and(not(isAbstract())).and(not(isNative()));
        var memoryType = named(MemoryBridge.MEMORY).or(named(MemoryBridge.STORE));
        var memoryMethods = namedOneOf("add", "set", "addAsync", "setAsync").and(takesArguments(1))
                .and(takesArgument(0, named("dev.langchain4j.data.message.ChatMessage"))
                        .or(takesArgument(0, named("[Ldev.langchain4j.data.message.ChatMessage;")))
                        .or(takesArgument(0, Iterable.class)).or(takesArgument(0, java.util.List.class)))
                .or(namedOneOf("messages", "messagesAsync", "clear").and(takesArguments(0)))
                .or(namedOneOf("getMessages", "getMessagesAsync", "deleteMessages", "deleteMessagesAsync").and(takesArguments(Object.class)))
                .or(namedOneOf("updateMessages", "updateMessagesAsync").and(takesArguments(Object.class, java.util.List.class)))
                .and(isPublic()).and(not(isAbstract())).and(not(isNative())).and(not(isStatic()));

        ThreadLocal<Boolean> failedTransform = new ThreadLocal<>();
        var transformer = new AgentBuilder.Default()
                .disableClassFormatChanges()
                .ignore(nameStartsWith("net.bytebuddy.").or(nameStartsWith("io.agentsecurity.agent."))
                        .or(nameStartsWith("io.agentsecurity.core.")).or(nameStartsWith("io.agentsecurity.policy.")).or(nameStartsWith("io.agentsecurity.shaded."))
                        .or(nameStartsWith("java.")).or(nameStartsWith("jdk.")).or(nameStartsWith("sun.")))
                .with(new AgentBuilder.Listener.Adapter() {
                    @Override public void onTransformation(TypeDescription type, ClassLoader loader, JavaModule module,
                                                           boolean loaded, DynamicType dynamicType) {
                        System.err.println("[agent-security] instrumented=" + type.getName());
                    }
                    @Override public void onError(String type, ClassLoader loader, JavaModule module, boolean loaded, Throwable error) {
                        Bridge.transformationFailed();
                        failedTransform.set(Boolean.TRUE);
                        System.err.println("[agent-security] TRANSFORM_ERROR type=" + type + " error=" + error.getClass().getName());
                    }
                })
                .type(modelType.or(hasSuperType(modelType)).or(toolType).or(hasSuperType(toolType))
                        .or(named("dev.langchain4j.service.tool.ToolService")))
                .transform((builder, type, loader, module, domain) -> builder
                        .visit(Advice.to(SyncAdvice.class).on(methods.and(not(returns(void.class)))
                                .and(not(returns(CompletableFuture.class)))
                                .and(not(returns(named("java.util.concurrent.Flow$Publisher"))))))
                        .visit(Advice.to(StreamInputAdvice.class).on(methods.and(returns(void.class))))
                        .visit(Advice.to(FutureAdvice.class).on(methods.and(returns(CompletableFuture.class))))
                        .visit(Advice.to(ErrorHandlerAdvice.class).on(named("toolErrorResult")
                                .and(takesArgument(0, Exception.class))))
                        .visit(Advice.to(ExecutorArgumentAdvice.class).on(named("executeToolsConcurrently").and(takesArguments(java.util.concurrent.Executor.class))))
                        .visit(Advice.to(ReactiveAdvice.class).on(methods.and(returns(named("java.util.concurrent.Flow$Publisher"))))))
                .type(named("dev.langchain4j.internal.DefaultExecutorProvider"))
                .transform((builder, type, loader, module, domain) -> builder
                        .visit(Advice.to(ExecutorReturnAdvice.class).on(named("getDefaultExecutor").and(takesArguments(0))))
                        .visit(Advice.to(ExecutorServiceReturnAdvice.class).on(named("getDefaultExecutorService").and(takesArguments(0)))))
                .type(ragType.or(hasSuperType(ragType)).and(not(hasSuperType(named("java.lang.reflect.Proxy")))))
                .transform((builder, type, loader, module, domain) -> builder
                        .visit(Advice.to(RagSyncAdvice.class).on(ragMethods.and(not(returns(CompletableFuture.class)))))
                        .visit(Advice.to(RagFutureAdvice.class).on(ragMethods.and(returns(CompletableFuture.class))))
                        .visit(Advice.to(RagConstructorAdvice.class).on(isConstructor()
                                .and(isDeclaredBy(named("dev.langchain4j.rag.DefaultRetrievalAugmentor"))))))
                .type(named("dev.langchain4j.service.AiServices").or(hasSuperType(named("dev.langchain4j.service.AiServices"))))
                .transform((builder, type, loader, module, domain) -> builder
                        .visit(Advice.to(RagRegistrationAdvice.class).on(namedOneOf("contentRetriever", "retrievalAugmentor")
                                .and(takesArguments(1)).and(not(isAbstract())))))
                .type(memoryType.or(hasSuperType(memoryType)).and(not(hasSuperType(named("java.lang.reflect.Proxy")))))
                .transform((builder, type, loader, module, domain) -> builder
                        .visit(Advice.to(MemoryWriteAdvice.class).on(memoryMethods.and(returns(void.class))))
                        .visit(Advice.to(MemoryReadAdvice.class).on(memoryMethods.and(returns(java.util.List.class))))
                        .visit(Advice.to(MemoryFutureAdvice.class).on(memoryMethods.and(returns(CompletableFuture.class)))))
                .type(named("dev.langchain4j.service.memory.ChatMemoryService"))
                .transform((builder, type, loader, module, domain) -> builder
                        .visit(Advice.to(MemoryDispatchAdvice.class).on(namedOneOf("getOrCreateChatMemory", "getChatMemory"))))
                .type(named("dev.langchain4j.memory.chat.MessageWindowChatMemory$Builder")
                        .or(named("dev.langchain4j.memory.chat.TokenWindowChatMemory$Builder")))
                .transform((builder, type, loader, module, domain) -> builder
                        .visit(Advice.to(MemoryStoreRegistrationAdvice.class).on(named("chatMemoryStore").and(takesArguments(1)))))
                .makeRaw();
        instrumentation.addTransformer(new FailClosedTransformer(transformer, failedTransform), false);
        System.err.println("[agent-security] installed; supported-langchain4j=1.20.0; mode=enforce; streaming=buffer-until-validated");
    }

    public static class SyncAdvice {
        @Advice.OnMethodEnter public static void enter(@Advice.Argument(0) Object request) { Bridge.before(request); }
        @Advice.OnMethodExit public static void exit(@Advice.Argument(0) Object request, @Advice.Return Object result) {
            Bridge.after(request, result);
        }
    }
    public static class MemoryWriteAdvice {
        @Advice.OnMethodEnter public static void enter(@Advice.This Object source, @Advice.Origin("#m") String method,
                @Advice.AllArguments(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object[] args) {
            Object[] replacement = args.clone(); MemoryBridge.before(source, method, replacement); args = replacement;
        }
    }
    public static class MemoryReadAdvice {
        @Advice.OnMethodEnter public static MemoryBridge.Call enter(@Advice.This Object source, @Advice.Origin("#m") String method,
                @Advice.AllArguments Object[] args) { return MemoryBridge.before(source, method, args); }
        @Advice.OnMethodExit public static void exit(@Advice.Enter MemoryBridge.Call call,
                @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) { result = MemoryBridge.after(call, result); }
    }
    public static class MemoryFutureAdvice {
        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
        public static Throwable enter(@Advice.This Object source, @Advice.Origin("#m") String method,
                @Advice.AllArguments(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object[] args,
                @Advice.Local("memoryCall") MemoryBridge.Call call) {
            try { Object[] replacement = args.clone(); call = MemoryBridge.before(source, method, replacement); args = replacement; return null; }
            catch (SecurityBlockedException denied) { return denied; }
        }
        @Advice.OnMethodExit public static void exit(@Advice.Enter Throwable denied, @Advice.Local("memoryCall") MemoryBridge.Call call,
                @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
            result = denied != null ? CompletableFuture.failedFuture(denied) : MemoryBridge.guardFuture(call, (CompletableFuture<?>) result);
        }
    }
    public static class MemoryDispatchAdvice {
        @Advice.OnMethodExit public static void exit(@Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
            result = MemoryBridge.wrap(result, MemoryBridge.MEMORY);
        }
    }
    public static class MemoryStoreRegistrationAdvice {
        @Advice.OnMethodEnter public static void enter(@Advice.Argument(value = 0, readOnly = false, typing = Assigner.Typing.DYNAMIC) Object store) {
            store = MemoryBridge.wrap(store, MemoryBridge.STORE);
        }
    }
    public static class RagSyncAdvice {
        @Advice.OnMethodEnter public static void enter(@Advice.This Object source, @Advice.Argument(0) Object request,
                @Advice.Origin("#m") String method) { RagBridge.before(source, request, method); }
        @Advice.OnMethodExit public static void exit(@Advice.This Object source, @Advice.Argument(0) Object request,
                @Advice.Origin("#m") String method, @Advice.Return Object result) { RagBridge.after(source, request, method, result); }
    }
    public static class RagFutureAdvice {
        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
        public static Throwable enter(@Advice.This Object source, @Advice.Argument(0) Object request,
                @Advice.Origin("#m") String method, @Advice.Local("ragContext") SecurityContext context) {
            context = SecurityContexts.current();
            try { RagBridge.before(source, request, method); return null; }
            catch (SecurityBlockedException denied) { return denied; }
        }
        @Advice.OnMethodExit public static void exit(@Advice.This Object source, @Advice.Argument(0) Object request,
                @Advice.Origin("#m") String method, @Advice.Enter Throwable denied,
                @Advice.Local("ragContext") SecurityContext context,
                @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
            result = denied != null ? CompletableFuture.failedFuture(denied)
                    : RagBridge.guardFuture(source, request, method, (CompletableFuture<?>) result, context);
        }
    }
    public static class RagConstructorAdvice {
        @Advice.OnMethodExit public static void exit(
                @Advice.FieldValue(value = "queryTransformer", readOnly = false, typing = Assigner.Typing.DYNAMIC) Object transformer,
                @Advice.FieldValue(value = "queryRouter", readOnly = false, typing = Assigner.Typing.DYNAMIC) Object router,
                @Advice.FieldValue(value = "contentAggregator", readOnly = false, typing = Assigner.Typing.DYNAMIC) Object aggregator,
                @Advice.FieldValue(value = "executor", readOnly = false) java.util.concurrent.Executor executor) {
            transformer = RagBridge.wrap(transformer, "dev.langchain4j.rag.query.transformer.QueryTransformer", "transform");
            router = RagBridge.wrap(router, "dev.langchain4j.rag.query.router.QueryRouter", "route");
            aggregator = RagBridge.wrap(aggregator, "dev.langchain4j.rag.content.aggregator.ContentAggregator", "aggregate");
            executor = SecurityContexts.executor(executor);
        }
    }
    public static class RagRegistrationAdvice {
        @Advice.OnMethodEnter public static void enter(@Advice.Origin("#m") String method,
                @Advice.Argument(value = 0, readOnly = false, typing = Assigner.Typing.DYNAMIC) Object component) {
            component = method.equals("contentRetriever") ? RagBridge.wrap(component, RagBridge.RETRIEVER, "retrieve")
                    : RagBridge.wrap(component, RagBridge.AUGMENTOR, "augment");
        }
    }
    public static class StreamInputAdvice {
        @Advice.OnMethodEnter public static void enter(@Advice.Argument(0) Object request,
                @Advice.Origin("#t") String owner, @Advice.Origin("#m") String method,
                @Advice.AllArguments(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object[] arguments,
                @Advice.Local("guardedHandler") Object guardedHandler) {
            Bridge.before(request);
            // Known interface convenience methods only forward to doChat. Wrap at the provider boundary.
            // Concrete chat overrides still get their own guard, including calls that bypass doChat.
            if (owner.equals("dev.langchain4j.model.chat.StreamingChatModel") && method.equals("chat")) return;
            Object[] replacement = arguments.clone();
            int index = replacement.length - 1;
            guardedHandler = Bridge.guardStream(request, replacement[index]);
            replacement[index] = guardedHandler;
            arguments = replacement;
        }
        @Advice.OnMethodExit(onThrowable = Throwable.class) public static void exit(
                @Advice.Thrown Throwable error, @Advice.Local("guardedHandler") Object guardedHandler) {
            if (error != null && guardedHandler != null) Bridge.abortStream(guardedHandler);
        }
    }
    public static class FutureAdvice {
        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
        public static Throwable enter(@Advice.Argument(0) Object request, @Advice.Local("securityContext") SecurityContext context) {
            context = SecurityContexts.current();
            try { Bridge.before(request); return null; }
            catch (SecurityBlockedException denied) { return denied; }
        }
        @Advice.OnMethodExit public static void exit(@Advice.Argument(0) Object request, @Advice.Enter Throwable denied,
                @Advice.Local("securityContext") SecurityContext context,
                @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
            result = denied != null ? CompletableFuture.failedFuture(denied)
                    : Bridge.guardFuture(request, (CompletableFuture<?>) result, context);
        }
    }
    public static class ReactiveAdvice {
        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class)
        public static Throwable enter(@Advice.Argument(0) Object request) {
            try { Bridge.before(request); return null; }
            catch (SecurityBlockedException denied) { return denied; }
        }
        @Advice.OnMethodExit public static void exit(@Advice.Argument(0) Object request, @Advice.Enter Throwable denied,
                @Advice.Origin("#t") String owner, @Advice.Origin("#m") String method,
                @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object result) {
            if (denied != null) result = Bridge.failedPublisher(denied);
            // The standard cold chat publisher delegates to guarded doChat on each subscription.
            else if (!owner.equals("dev.langchain4j.model.chat.StreamingChatModel") || !method.equals("chat"))
                result = Bridge.guardPublisher(request, (java.util.concurrent.Flow.Publisher<?>) result);
            else result = Bridge.contextPublisher((java.util.concurrent.Flow.Publisher<?>) result, SecurityContexts.current());
        }
    }
    public static class ExecutorArgumentAdvice {
        @Advice.OnMethodEnter public static void enter(@Advice.Argument(value = 0, readOnly = false) java.util.concurrent.Executor executor) {
            if (executor != null) executor = SecurityContexts.executor(executor);
        }
    }
    public static class ExecutorReturnAdvice {
        @Advice.OnMethodExit public static void exit(@Advice.Return(readOnly = false) java.util.concurrent.Executor executor) {
            executor = SecurityContexts.executor(executor);
        }
    }
    public static class ExecutorServiceReturnAdvice {
        @Advice.OnMethodExit public static void exit(@Advice.Return(readOnly = false) java.util.concurrent.ExecutorService executor) {
            executor = SecurityContexts.executorService(executor);
        }
    }
    public static class ErrorHandlerAdvice {
        @Advice.OnMethodEnter public static void enter(@Advice.Argument(0) Exception error) {
            Throwable cause = error;
            for (int depth = 0; cause != null && depth < 64; depth++) {
                if (cause instanceof SecurityBlockedException denied) throw denied;
                if (cause.getCause() == cause) break;
                cause = cause.getCause();
            }
        }
    }
}
