package io.agentsecurity.fixture;

import com.sun.net.httpserver.HttpServer;
import dev.langchain4j.agent.tool.Tool;
import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.chat.response.StreamingChatResponseHandler;
import dev.langchain4j.model.openai.OpenAiChatModel;
import dev.langchain4j.model.openai.OpenAiStreamingChatModel;
import dev.langchain4j.service.AiServices;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Spring Boot 集成测试入口，用于验证嵌套 JAR 类加载、插件发现和本机模型协议，不是 SDK 运行依赖。 */
@SpringBootApplication
public class BootFixture implements ApplicationRunner {

    public interface Assistant {

        String chat(String message);
    }

    private static final AtomicInteger modelCalls = new AtomicInteger();

    private static final AtomicInteger toolCalls = new AtomicInteger();

    private static final AtomicInteger chunks = new AtomicInteger();

    public static void main(String[] args) {
        try (var application = SpringApplication.run(BootFixture.class, args)) {}
    }

    public static class Tools {

        @Tool
        public String sendEmail() {
            toolCalls.incrementAndGet();
            return "sent";
        }

        @Tool
        public String readCustomer() {
            toolCalls.incrementAndGet();
            return "record";
        }

        @Tool
        public String lookupCustomer(String customerId, int limit) {
            toolCalls.incrementAndGet();
            if (!customerId.equals("demo-customer") || limit < 1 || limit > 10) {
                throw new IllegalArgumentException("unexpected fixture arguments");
            }
            return "bounded record";
        }
    }

    public static class MockModel implements ChatModel {

        private final String tool;

        private final String arguments;

        MockModel(String tool) {
            this(tool, "{}");
        }

        MockModel(String tool, String arguments) {
            this.tool = tool;
            this.arguments = arguments;
        }

        @Override
        public ChatResponse doChat(ChatRequest request) {
            int count = modelCalls.incrementAndGet();
            return ChatResponse.builder()
                    .aiMessage(
                            count == 1 && tool != null
                                    ? AiMessage.from(
                                            ToolExecutionRequest.builder()
                                                    .id("one")
                                                    .name(tool)
                                                    .arguments(arguments)
                                                    .build())
                                    : AiMessage.from("done"))
                    .build();
        }
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        String scenario = args.getOptionValues("scenario").get(0);
        if (scenario.startsWith("delegation-")) {
            DelegationFixture.run(scenario);
            return;
        }
        if (scenario.startsWith("context-")) {
            ContextFixture.run(scenario);
            return;
        }
        if (scenario.startsWith("rag-")) {
            RagFixture.run(scenario);
            return;
        }
        if (scenario.startsWith("memory-")) {
            MemoryFixture.run(scenario);
            return;
        }
        boolean blocked = false;
        try {
            if (scenario.startsWith("http-")) {
                runHttp(scenario);
            } else if (scenario.startsWith("args-")) {
                String arguments =
                        switch (scenario) {
                            case "args-allowed" -> "{\"customerId\":\"demo-customer\",\"limit\":2}";
                            case "args-escaped" ->
                                    "{\"customerId\":\"other-\\u0063ustomer\",\"limit\":2}";
                            case "args-duplicate" ->
                                    "{\"customerId\":\"demo-customer\",\"customerId\":\"other-customer\",\"limit\":2}";
                            default -> "{\"customerId\":\"other-customer\",\"limit\":2}";
                        };
                AiServices.builder(Assistant.class)
                        .chatModel(new MockModel("lookupCustomer", arguments))
                        .tools(new Tools())
                        .build()
                        .chat("lookup");
            } else {
                var model =
                        new MockModel(
                                scenario.equals("tool")
                                        ? "sendEmail"
                                        : scenario.equals("allowed") ? "readCustomer" : null);
                AiServices.builder(Assistant.class)
                        .chatModel(model)
                        .tools(new Tools())
                        .build()
                        .chat(
                                switch (scenario) {
                                    case "plugin" -> "PLUGIN_DENY";
                                    case "plugin-timeout" -> "PLUGIN_SLEEP";
                                    case "plugin-error" -> "PLUGIN_FAILURE";
                                    default -> "hello";
                                });
            }
        } catch (Exception exception) {
            Throwable error = exception;
            while (error != null
                    && !error.getClass()
                            .getName()
                            .equals("io.agentsecurity.core.SecurityBlockedException")) {
                error = error.getCause();
            }
            if (error == null) {
                throw exception;
            }
            blocked = true;
            System.out.println("BLOCK_REASON=" + error.getMessage());
        }
        var coverage = io.agentsecurity.core.health.AgentCoverage.global().snapshot();
        if (!coverage.installed()
                || coverage.failed()
                || coverage.transformations() == 0
                || coverage.detector() == null
                || coverage.audit() == null
                || coverage.versionChecksPassed() == 0
                || coverage.versionChecksFailed() != 0) {
            throw new IllegalStateException("Agent diagnostics missing across Boot classloader");
        }
        if (scenario.equals("plugin-timeout") && coverage.detector().timeouts() == 0) {
            throw new IllegalStateException("Detector timeout not visible in diagnostics");
        }
        System.out.println("AGENT_HEALTH_OK");
        System.out.printf(
                "BOOT_RESULT scenario=%s blocked=%s modelCalls=%d toolCalls=%d chunks=%d%n",
                scenario, blocked, modelCalls.get(), toolCalls.get(), chunks.get());
    }

    private static void runHttp(String scenario) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        boolean stream = scenario.contains("stream") || scenario.contains("reactive");
        boolean secret = scenario.endsWith("output");
        server.createContext(
                "/v1/chat/completions",
                exchange -> {
                    modelCalls.incrementAndGet();
                    exchange.getRequestBody().readAllBytes();
                    String body;
                    if (stream) {
                        exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
                        body =
                                chunk(secret ? "DEMO_SECRET_" : "hel")
                                        + chunk(secret ? "123" : "lo")
                                        + "data: {\"id\":\"local\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
                                        + "data: [DONE]\n\n";
                    } else {
                        exchange.getResponseHeaders().set("Content-Type", "application/json");
                        body =
                                "{\"id\":\"local\",\"model\":\"mock\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\""
                                        + (secret ? "DEMO_SECRET_123" : "hello")
                                        + "\"},\"finish_reason\":\"stop\"}]}";
                    }
                    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200, bytes.length);
                    try (var output = exchange.getResponseBody()) {
                        output.write(bytes);
                    }
                });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1";
            String input = scenario.endsWith("input") ? "IGNORE_SECURITY_TEST" : "hello";
            if (stream) {
                var completion = new CompletableFuture<ChatResponse>();
                var model =
                        OpenAiStreamingChatModel.builder()
                                .baseUrl(url)
                                .apiKey("local-test-only")
                                .modelName("mock")
                                .timeout(Duration.ofSeconds(5))
                                .build();
                if (scenario.contains("reactive-text")) {
                    model.chat(input)
                            .subscribe(
                                    new java.util.concurrent.Flow.Subscriber<>() {

                                        java.util.concurrent.Flow.Subscription subscription;

                                        @Override
                                        public void onSubscribe(
                                                java.util.concurrent.Flow.Subscription
                                                        subscription) {
                                            this.subscription = subscription;
                                            subscription.request(1);
                                        }

                                        @Override
                                        public void onNext(String text) {
                                            chunks.incrementAndGet();
                                            subscription.request(1);
                                        }

                                        @Override
                                        public void onError(Throwable error) {
                                            completion.completeExceptionally(error);
                                        }

                                        @Override
                                        public void onComplete() {
                                            completion.complete(null);
                                        }
                                    });
                } else if (scenario.contains("reactive")) {
                    model.chat(
                                    ChatRequest.builder()
                                            .messages(
                                                    dev.langchain4j.data.message.UserMessage.from(
                                                            input))
                                            .build())
                            .subscribe(
                                    new java.util.concurrent.Flow.Subscriber<>() {

                                        java.util.concurrent.Flow.Subscription subscription;

                                        ChatResponse response;

                                        @Override
                                        public void onSubscribe(
                                                java.util.concurrent.Flow.Subscription
                                                        subscription) {
                                            this.subscription = subscription;
                                            if (scenario.endsWith("cancel")) {
                                                subscription.cancel();
                                                completion.complete(null);
                                            } else {
                                                subscription.request(1);
                                            }
                                        }

                                        @Override
                                        public void onNext(
                                                dev.langchain4j.model.chat.response
                                                                .ChatModelStreamingEvent
                                                        event) {
                                            if (event
                                                    instanceof
                                                    dev.langchain4j.model.chat.response
                                                            .PartialResponse) {
                                                chunks.incrementAndGet();
                                            }
                                            if (event
                                                    instanceof
                                                    dev.langchain4j.model.chat.response
                                                                            .CompleteResponse
                                                                    complete) {
                                                response = complete.chatResponse();
                                            }
                                            subscription.request(1);
                                        }

                                        @Override
                                        public void onError(Throwable error) {
                                            completion.completeExceptionally(error);
                                        }

                                        @Override
                                        public void onComplete() {
                                            completion.complete(response);
                                        }
                                    });
                } else {
                    model.chat(
                            input,
                            new StreamingChatResponseHandler() {

                                @Override
                                public void onPartialResponse(String text) {
                                    chunks.incrementAndGet();
                                }

                                @Override
                                public void onCompleteResponse(ChatResponse response) {
                                    completion.complete(response);
                                }

                                @Override
                                public void onError(Throwable error) {
                                    completion.completeExceptionally(error);
                                }
                            });
                }
                completion.get(10, TimeUnit.SECONDS);
            } else {
                var model =
                        OpenAiChatModel.builder()
                                .baseUrl(url)
                                .apiKey("local-test-only")
                                .modelName("mock")
                                .timeout(Duration.ofSeconds(5))
                                .maxRetries(0)
                                .build();
                if (scenario.contains("async")) {
                    model.chatAsync(input).get(10, TimeUnit.SECONDS);
                } else {
                    model.chat(input);
                }
            }
        } finally {
            server.stop(0);
        }
    }

    private static String chunk(String text) {
        return "data: {\"id\":\"local\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\""
                + text
                + "\"},\"finish_reason\":null}]}\n\n";
    }
}
