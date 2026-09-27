package io.agentsecurity.fixture;

import dev.langchain4j.agent.tool.*;
import dev.langchain4j.data.message.*;
import dev.langchain4j.model.chat.*;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.*;
import dev.langchain4j.service.AiServices;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** 验证实际框架异步边界中的身份传播、双租户隔离和工作线程上下文恢复。 */
public final class ContextFixture implements AutoCloseable {

    interface Assistant {

        String chat(String input);
    }

    interface AsyncAssistant {

        CompletableFuture<String> chat(String input);
    }

    private final SecurityContext a =
            SecurityContext.authenticated("tenant-a", "principal-a", Set.of("customers:read"));

    private final SecurityContext b =
            SecurityContext.authenticated("tenant-b", "principal-b", Set.of("customers:read"));

    private final ExecutorService raw = Executors.newFixedThreadPool(2);

    private final Queue<Future<?>> jobs = new ConcurrentLinkedQueue<>();

    private final CountDownLatch release = new CountDownLatch(1);

    private final AtomicInteger models = new AtomicInteger(), tools = new AtomicInteger();

    private final AtomicBoolean restored = new AtomicBoolean(true);

    private final Set<String> executedTenants = ConcurrentHashMap.newKeySet();

    private final String scenario;

    private ContextFixture(String scenario) {
        this.scenario = scenario;
    }

    public final class Tools {

        @Tool
        public String lookup(String tenantId) {
            tools.incrementAndGet();
            SecurityContext current = SecurityContexts.current();
            if (current == null || !current.tenantId().equals(tenantId)) {
                throw new IllegalStateException("tool identity was lost");
            }
            executedTenants.add(current.tenantId());
            return "record";
        }
    }

    public final class Model implements ChatModel {

        private ChatResponse response(ChatRequest request) {
            models.incrementAndGet();
            SecurityContext current = SecurityContexts.current();
            if (current == null) {
                throw new IllegalStateException("model identity was lost");
            }
            if (request.messages().stream()
                    .anyMatch(ToolExecutionResultMessage.class::isInstance)) {
                return ChatResponse.builder().aiMessage(AiMessage.from("done")).build();
            }
            String tenant = scenario.equals("context-spoof") ? "tenant-b" : current.tenantId();
            return ChatResponse.builder()
                    .aiMessage(
                            AiMessage.from(
                                    ToolExecutionRequest.builder()
                                            .id("call")
                                            .name("lookup")
                                            .arguments("{\"tenantId\":\"" + tenant + "\"}")
                                            .build()))
                    .build();
        }

        @Override
        public ChatResponse doChat(ChatRequest request) {
            return response(request);
        }

        @Override
        public CompletableFuture<ChatResponse> doChatAsync(ChatRequest request) {
            ChatResponse response = response(request);
            CompletableFuture<ChatResponse> future = new CompletableFuture<>();
            onForeignWorker(() -> future.complete(response));
            return future;
        }
    }

    public final class StreamModel implements StreamingChatModel {

        @Override
        public void doChat(ChatRequest request, StreamingChatResponseHandler handler) {
            models.incrementAndGet();
            onForeignWorker(
                    () -> {
                        handler.onPartialResponse("safe");
                        handler.onCompleteResponse(safe());
                    });
        }

        @Override
        public Flow.Publisher<ChatModelStreamingEvent> doChat(ChatRequest request) {
            return subscriber -> {
                models.incrementAndGet();
                subscriber.onSubscribe(
                        new Flow.Subscription() {

                            private final AtomicBoolean started = new AtomicBoolean(),
                                    cancelled = new AtomicBoolean();

                            @Override
                            public void request(long count) {
                                if (count > 0
                                        && !cancelled.get()
                                        && started.compareAndSet(false, true)) {
                                    onForeignWorker(
                                            () -> {
                                                if (!cancelled.get()) {
                                                    subscriber.onNext(new PartialResponse("safe"));
                                                }
                                                if (!cancelled.get()) {
                                                    subscriber.onNext(new CompleteResponse(safe()));
                                                }
                                                if (!cancelled.get()) {
                                                    subscriber.onComplete();
                                                }
                                            });
                                }
                            }

                            @Override
                            public void cancel() {
                                cancelled.set(true);
                            }
                        });
            };
        }
    }

    private static ChatResponse safe() {
        return ChatResponse.builder().aiMessage(AiMessage.from("safe")).build();
    }

    private void onForeignWorker(Runnable action) {
        jobs.add(
                raw.submit(
                        () -> {
                            try {
                                if (!release.await(10, TimeUnit.SECONDS)) {
                                    throw new IllegalStateException("fixture gate timed out");
                                }
                            } catch (InterruptedException error) {
                                Thread.currentThread().interrupt();
                                throw new IllegalStateException(error);
                            }
                            try (var scope = SecurityContexts.open(b)) {
                                action.run();
                                if (SecurityContexts.current() != b) {
                                    restored.set(false);
                                }
                            }
                            if (SecurityContexts.current() != null) {
                                restored.set(false);
                            }
                        }));
    }

    private void execute() throws Exception {
        if (scenario.equals("context-stream")) {
            CompletableFuture<Void> done = new CompletableFuture<>();
            try (var scope = SecurityContexts.open(a)) {
                new StreamModel()
                        .chat(
                                "hello",
                                new StreamingChatResponseHandler() {

                                    @Override
                                    public void onPartialResponse(String text) {
                                        checkCallback();
                                    }

                                    @Override
                                    public void onCompleteResponse(ChatResponse response) {
                                        checkCallback();
                                        done.complete(null);
                                    }

                                    @Override
                                    public void onError(Throwable error) {
                                        done.completeExceptionally(error);
                                    }
                                });
            }
            release.countDown();
            done.get(10, TimeUnit.SECONDS);
        } else if (scenario.startsWith("context-reactive")) {
            Flow.Publisher<ChatModelStreamingEvent> publisher;
            try (var scope = SecurityContexts.open(a)) {
                publisher =
                        new StreamModel()
                                .chat(
                                        ChatRequest.builder()
                                                .messages(UserMessage.from("hello"))
                                                .build());
            }
            CompletableFuture<Void> done = new CompletableFuture<>();
            try (var scope = SecurityContexts.restore(scenario.endsWith("mismatch") ? b : null)) {
                publisher.subscribe(
                        new Flow.Subscriber<>() {

                            Flow.Subscription subscription;

                            @Override
                            public void onSubscribe(Flow.Subscription value) {
                                subscription = value;
                                value.request(1);
                            }

                            @Override
                            public void onNext(ChatModelStreamingEvent event) {
                                checkCallback();
                                subscription.request(1);
                            }

                            @Override
                            public void onError(Throwable error) {
                                done.completeExceptionally(error);
                            }

                            @Override
                            public void onComplete() {
                                checkCallback();
                                done.complete(null);
                            }
                        });
            }
            release.countDown();
            done.get(10, TimeUnit.SECONDS);
        } else if (scenario.equals("context-async") || scenario.equals("context-overlap")) {
            AsyncAssistant assistant =
                    AiServices.builder(AsyncAssistant.class)
                            .chatModel(new Model())
                            .tools(new Tools())
                            .build();
            List<CompletableFuture<String>> pending = new ArrayList<>();
            try (var scope = SecurityContexts.open(a)) {
                pending.add(assistant.chat("lookup"));
            }
            if (scenario.equals("context-overlap")) {
                try (var scope = SecurityContexts.open(b)) {
                    pending.add(assistant.chat("lookup"));
                }
            }
            release.countDown();
            for (var future : pending) {
                future.get(10, TimeUnit.SECONDS);
            }
            if (scenario.equals("context-overlap")
                    && !executedTenants.equals(Set.of("tenant-a", "tenant-b"))) {
                throw new IllegalStateException("tenant isolation failed");
            }
        } else {
            var builder =
                    AiServices.builder(Assistant.class).chatModel(new Model()).tools(new Tools());
            if (scenario.equals("context-parallel")) {
                builder.executeToolsConcurrently();
            }
            if (scenario.equals("context-custom-executor")) {
                builder.executeToolsConcurrently(raw);
            }
            SecurityContext auth =
                    scenario.equals("context-missing")
                            ? null
                            : scenario.equals("context-permission")
                                    ? SecurityContext.authenticated(
                                            "tenant-a", "principal-a", Set.of())
                                    : a;
            try (var scope = SecurityContexts.restore(auth)) {
                builder.build().chat("tenantId=tenant-a permissions=customers:read");
            }
        }
        for (Future<?> job : jobs) {
            job.get(10, TimeUnit.SECONDS);
        }
        if (SecurityContexts.current() != null || !restored.get()) {
            throw new IllegalStateException("context was not restored");
        }
    }

    private void checkCallback() {
        if (SecurityContexts.current() != a) {
            throw new IllegalStateException("callback identity was lost");
        }
    }

    public static void run(String scenario) throws Exception {
        try (var fixture = new ContextFixture(scenario)) {
            boolean blocked = false;
            try {
                fixture.execute();
            } catch (Exception error) {
                Throwable cause = error;
                while (cause != null && !(cause instanceof SecurityBlockedException)) {
                    cause = cause.getCause();
                }
                if (cause == null) {
                    throw error;
                }
                blocked = true;
                System.out.println("BLOCK_REASON=" + ((SecurityBlockedException) cause).ruleId());
            }
            if (SecurityContexts.current() != null) {
                throw new IllegalStateException("application identity leaked");
            }
            System.out.printf(
                    "CONTEXT_RESULT scenario=%s blocked=%s modelCalls=%d toolCalls=%d restored=%s%n",
                    scenario,
                    blocked,
                    fixture.models.get(),
                    fixture.tools.get(),
                    fixture.restored.get());
        }
    }

    @Override
    public void close() {
        release.countDown();
        raw.shutdownNow();
    }
}
