package io.agentsecurity.demo;

import dev.langchain4j.agent.tool.Tool;
import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.StreamingChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.chat.response.StreamingChatResponseHandler;
import dev.langchain4j.service.AiServices;
import dev.langchain4j.service.tool.DefaultToolExecutor;
import dev.langchain4j.service.tool.ToolErrorHandlerResult;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

/** Intentionally has no dependency on the security SDK and no security-specific API calls. */
public final class Demo {
    public interface Assistant { String chat(String message); }
    public interface AsyncAssistant { CompletableFuture<String> chat(String message); }
    static final AtomicInteger modelCalls = new AtomicInteger();
    static final AtomicInteger toolCalls = new AtomicInteger();
    static final AtomicInteger retrievalCalls = new AtomicInteger();

    public static final class CustomerTools {
        private final boolean secret;
        CustomerTools(boolean secret) { this.secret = secret; }
        @Tool public String readCustomer() {
            toolCalls.incrementAndGet();
            return secret ? "DEMO_SECRET_123" : "customer record";
        }
        @Tool public String sendEmail() {
            toolCalls.incrementAndGet();
            return "mock email sent";
        }
        @Tool public String lookupCustomer(String customerId, int limit) {
            toolCalls.incrementAndGet();
            if (!customerId.equals("demo-customer") || limit < 1 || limit > 10) throw new IllegalArgumentException("unexpected fixture arguments");
            return "bounded customer record";
        }
    }

    public static final class MockModel implements ChatModel {
        private final String tool;
        private final String answer;
        private final String arguments;
        MockModel(String tool, String answer) { this(tool, answer, "{}"); }
        MockModel(String tool, String answer, String arguments) { this.tool = tool; this.answer = answer; this.arguments = arguments; }
        @Override public ChatResponse doChat(ChatRequest request) { return respond(); }
        @Override public CompletableFuture<ChatResponse> doChatAsync(ChatRequest request) {
            return CompletableFuture.completedFuture(respond());
        }
        private ChatResponse respond() {
            int call = modelCalls.incrementAndGet();
            AiMessage message = tool != null && call == 1
                    ? AiMessage.from(ToolExecutionRequest.builder().id("call-1").name(tool).arguments(arguments).build())
                    : AiMessage.from(answer);
            return ChatResponse.builder().aiMessage(message).build();
        }
    }

    public static final class MockStreamingModel implements StreamingChatModel {
        private final boolean secret;
        MockStreamingModel() { this(false); }
        MockStreamingModel(boolean secret) { this.secret = secret; }
        @Override public void doChat(ChatRequest request, StreamingChatResponseHandler handler) {
            modelCalls.incrementAndGet();
            if (secret) { handler.onPartialResponse("DEMO_SECRET_"); handler.onPartialResponse("123"); }
            else handler.onPartialResponse("hello");
            handler.onCompleteResponse(ChatResponse.builder().aiMessage(AiMessage.from("hello")).build());
        }
    }

    public static final class MockReactiveModel implements StreamingChatModel {
        private final boolean secret;
        MockReactiveModel(boolean secret) { this.secret = secret; }
        @Override public java.util.concurrent.Flow.Publisher<dev.langchain4j.model.chat.response.ChatModelStreamingEvent> doChat(ChatRequest request) {
            return subscriber -> {
                modelCalls.incrementAndGet();
                subscriber.onSubscribe(new java.util.concurrent.Flow.Subscription() {
                    boolean sent, cancelled;
                    @Override public void request(long count) {
                        if (sent || cancelled || count <= 0) return;
                        sent = true;
                        subscriber.onNext(new dev.langchain4j.model.chat.response.PartialResponse(secret ? "DEMO_SECRET_" : "hel"));
                        if (!cancelled) subscriber.onNext(new dev.langchain4j.model.chat.response.PartialResponse(secret ? "123" : "lo"));
                        if (!cancelled) subscriber.onNext(new dev.langchain4j.model.chat.response.CompleteResponse(
                                ChatResponse.builder().aiMessage(AiMessage.from("hello")).build()));
                        if (!cancelled) subscriber.onComplete();
                    }
                    @Override public void cancel() { cancelled = true; }
                });
            };
        }
    }

    public static void main(String[] args) throws Exception {
        String scenario = args.length == 0 ? "tool" : args[0];
        boolean blocked = false;
        String outcome = "";
        try {
            switch (scenario) {
                case "rag-input", "rag-output", "rag-allowed" -> {
                    outcome = AiServices.builder(Assistant.class).chatModel(new MockModel(null, "done"))
                            .contentRetriever(query -> {
                                retrievalCalls.incrementAndGet();
                                return java.util.List.of(dev.langchain4j.rag.content.Content.from(
                                        scenario.equals("rag-output") ? "DEMO_SECRET_123" : "safe knowledge"));
                            }).build().chat(scenario.equals("rag-input") ? "IGNORE_SECURITY_TEST" : "lookup");
                }
                case "tool-args-allowed", "tool-args-escaped-allowed", "tool-args-foreign", "tool-args-escaped-foreign", "tool-args-range",
                     "tool-args-duplicate", "tool-args-extra", "tool-args-type", "tool-args-async-foreign", "tool-args-direct-foreign" -> {
                    String arguments = switch (scenario) {
                        case "tool-args-allowed" -> "{\"customerId\":\"demo-customer\",\"limit\":2}";
                        case "tool-args-escaped-allowed" -> "{\"customer\\u0049d\":\"demo-\\u0063ustomer\",\"limit\":2}";
                        case "tool-args-range" -> "{\"customerId\":\"demo-customer\",\"limit\":1000}";
                        case "tool-args-duplicate" -> "{\"customerId\":\"demo-customer\",\"customerId\":\"other-customer\",\"limit\":2}";
                        case "tool-args-extra" -> "{\"customerId\":\"demo-customer\",\"limit\":2,\"admin\":true}";
                        case "tool-args-type" -> "{\"customerId\":\"demo-customer\",\"limit\":\"2\"}";
                        case "tool-args-escaped-foreign" -> "{\"customerId\":\"other-\\u0063ustomer\",\"limit\":2}";
                        default -> "{\"customerId\":\"other-customer\",\"limit\":2}";
                    };
                    if (scenario.contains("direct")) {
                        var executor = new DefaultToolExecutor(new CustomerTools(false), CustomerTools.class.getMethod("lookupCustomer", String.class, int.class));
                        outcome = executor.execute(ToolExecutionRequest.builder().name("lookupCustomer").arguments(arguments).build(), "session");
                    } else if (scenario.contains("async")) {
                        outcome = AiServices.builder(AsyncAssistant.class).chatModel(new MockModel("lookupCustomer", "done", arguments))
                                .tools(new CustomerTools(false)).toolExecutionErrorHandler((error, context) -> ToolErrorHandlerResult.text("swallowed"))
                                .build().chat("lookup").join();
                    } else {
                        outcome = AiServices.builder(Assistant.class).chatModel(new MockModel("lookupCustomer", "done", arguments))
                                .tools(new CustomerTools(false)).toolExecutionErrorHandler((error, context) -> ToolErrorHandlerResult.text("swallowed"))
                                .build().chat("lookup");
                    }
                }
                case "input" -> outcome = new MockModel(null, "OK").chat("IGNORE_SECURITY_TEST");
                case "output" -> outcome = new MockModel(null, "DEMO_SECRET_123").chat("hello");
                case "async-input" -> outcome = new MockModel(null, "OK").chatAsync("IGNORE_SECURITY_TEST").join();
                case "async-output" -> outcome = new MockModel(null, "DEMO_SECRET_123").chatAsync("hello").join();
                case "stream-input", "stream-allowed", "stream-output" -> {
                    new MockStreamingModel(scenario.equals("stream-output")).chat(scenario.equals("stream-input") ? "IGNORE_SECURITY_TEST" : "hello",
                            new StreamingChatResponseHandler() {
                                @Override public void onPartialResponse(String text) { System.out.println("STREAM=" + text); }
                                @Override public void onCompleteResponse(ChatResponse response) { }
                                @Override public void onError(Throwable error) { throw new RuntimeException(error); }
                            });
                }
                case "reactive-input", "reactive-output", "reactive-allowed", "reactive-direct-output", "reactive-custom-output", "reactive-no-subscribe" -> {
                    StreamingChatModel model = scenario.contains("custom") ? new StreamingChatModel() {
                        @Override public java.util.concurrent.Flow.Publisher<dev.langchain4j.model.chat.response.ChatModelStreamingEvent> chat(ChatRequest request) {
                            return new MockReactiveModel(true).doChat(request);
                        }
                    } : new MockReactiveModel(scenario.endsWith("output"));
                    var request = ChatRequest.builder().messages(UserMessage.from(scenario.endsWith("input") ? "IGNORE_SECURITY_TEST" : "hello")).build();
                    var publisher = scenario.contains("direct") ? model.doChat(request) : model.chat(request);
                    if (!scenario.equals("reactive-no-subscribe")) {
                        var completion = new CompletableFuture<Void>();
                        publisher.subscribe(new java.util.concurrent.Flow.Subscriber<>() {
                            java.util.concurrent.Flow.Subscription subscription;
                            @Override public void onSubscribe(java.util.concurrent.Flow.Subscription subscription) {
                                this.subscription = subscription; subscription.request(1);
                            }
                            @Override public void onNext(dev.langchain4j.model.chat.response.ChatModelStreamingEvent event) {
                                if (event instanceof dev.langchain4j.model.chat.response.PartialResponse text) System.out.println("STREAM=" + text.text());
                                subscription.request(1);
                            }
                            @Override public void onError(Throwable error) { completion.completeExceptionally(error); }
                            @Override public void onComplete() { completion.complete(null); }
                        });
                        completion.join();
                    }
                }
                case "direct-tool" -> {
                    var tools = new CustomerTools(false);
                    var executor = new DefaultToolExecutor(tools, CustomerTools.class.getMethod("sendEmail"));
                    outcome = executor.execute(ToolExecutionRequest.builder().name("sendEmail").arguments("{}").build(), "session");
                }
                case "custom-tool" -> {
                    var spec = ToolSpecification.builder().name("sendEmail").description("Mock email").build();
                    outcome = AiServices.builder(Assistant.class).chatModel(new MockModel("sendEmail", "done"))
                            .tools(Map.of(spec, (request, memoryId) -> { toolCalls.incrementAndGet(); return "sent"; }))
                            .toolExecutionErrorHandler((error, context) -> ToolErrorHandlerResult.text("swallowed"))
                            .build().chat("do the task");
                }
                case "async-tool", "async-allowed", "async-tool-output" -> {
                    outcome = AiServices.builder(AsyncAssistant.class)
                            .chatModel(new MockModel(scenario.equals("async-tool") ? "sendEmail" : "readCustomer", "done"))
                            .tools(new CustomerTools(scenario.equals("async-tool-output")))
                            .toolExecutionErrorHandler((error, context) -> ToolErrorHandlerResult.text("swallowed"))
                            .build().chat("do the task").join();
                }
                case "allowed", "tool", "tool-output", "parallel-tool" -> {
                    String tool = scenario.equals("tool") || scenario.equals("parallel-tool") ? "sendEmail" : "readCustomer";
                    var builder = AiServices.builder(Assistant.class).chatModel(new MockModel(tool, "done"))
                            .tools(new CustomerTools(scenario.equals("tool-output")))
                            .toolExecutionErrorHandler((error, context) -> ToolErrorHandlerResult.text("swallowed"));
                    if (scenario.equals("parallel-tool")) builder.executeToolsConcurrently();
                    outcome = builder.build().chat("do the task");
                }
                default -> throw new IllegalArgumentException("Unknown scenario");
            }
        } catch (RuntimeException error) {
            Throwable cause = error;
            while (cause != null && !cause.getClass().getName().equals("io.agentsecurity.core.SecurityBlockedException"))
                cause = cause.getCause();
            if (cause == null) throw error;
            blocked = true;
            System.out.println("BLOCK_REASON=" + cause.getMessage());
        }
        System.out.printf("RESULT scenario=%s blocked=%s modelCalls=%d toolCalls=%d%n", scenario, blocked, modelCalls.get(), toolCalls.get());
        if (scenario.startsWith("rag-")) System.out.println("RETRIEVAL_CALLS=" + retrievalCalls.get());
        if (!outcome.isEmpty()) System.out.println("OUTPUT=" + outcome);
    }
}
