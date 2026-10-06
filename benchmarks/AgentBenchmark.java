import dev.langchain4j.agent.tool.Tool;
import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.StreamingChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.chat.response.StreamingChatResponseHandler;
import dev.langchain4j.service.tool.DefaultToolExecutor;
import java.lang.management.ManagementFactory;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/** 真实插桩与审计的本机诊断：模型及工具是确定性本地模拟，不代表真实模型服务 SLA。 */
public final class AgentBenchmark {
    private static final AtomicLong MODEL_CALLS = new AtomicLong();
    private static final AtomicLong TOOL_CALLS = new AtomicLong();

    public static final class EchoTools {
        @Tool
        public String echo(String value) {
            TOOL_CALLS.incrementAndGet();
            return value;
        }
    }

    private record Metrics(
            long[] latency,
            long[] firstByte,
            long elapsed,
            long gcCount,
            long gcMillis,
            long heapBefore,
            long heapAfter,
            long modelCalls,
            long toolCalls,
            long pluginChecks) {}

    public static void main(String[] args) throws Exception {
        String mode = args[0];
        String scenario = args[1];
        int threads = Integer.parseInt(args[2]);
        int iterations = Integer.parseInt(args[3]);
        int chars = Integer.parseInt(args[4]);
        int streamDelay = Integer.parseInt(args[5]);
        int warmup = Math.min(iterations, 500);
        String text = "A".repeat(chars);
        ChatRequest request = ChatRequest.builder().messages(UserMessage.from(text)).build();
        ChatResponse response = ChatResponse.builder().aiMessage(AiMessage.from(text)).build();
        ChatModel model =
                new ChatModel() {
                    @Override
                    public ChatResponse doChat(ChatRequest ignored) {
                        MODEL_CALLS.incrementAndGet();
                        return response;
                    }
                };
        StreamingChatModel stream =
                new StreamingChatModel() {
                    @Override
                    public void doChat(ChatRequest ignored, StreamingChatResponseHandler handler) {
                        MODEL_CALLS.incrementAndGet();
                        handler.onPartialResponse(text.substring(0, chars / 2));
                        try {
                            if (streamDelay > 0) {
                                Thread.sleep(streamDelay);
                            }
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                            throw new IllegalStateException("探针流中断");
                        }
                        handler.onPartialResponse(text.substring(chars / 2));
                        handler.onCompleteResponse(response);
                    }
                };
        var tool =
                new DefaultToolExecutor(
                        new EchoTools(), EchoTools.class.getMethod("echo", String.class));
        var toolRequest =
                ToolExecutionRequest.builder()
                        .name("echo")
                        .arguments("{\"value\":\"" + text + "\"}")
                        .build();
        var pool = Executors.newFixedThreadPool(threads);
        try {
            for (int round = 0; round < 3; round++) {
                measure(
                        pool,
                        scenario,
                        threads,
                        warmup,
                        model,
                        stream,
                        request,
                        tool,
                        toolRequest,
                        text);
            }
            Metrics result =
                    measure(
                            pool,
                            scenario,
                            threads,
                            iterations,
                            model,
                            stream,
                            request,
                            tool,
                            toolRequest,
                            text);
            long operations = (long) threads * iterations;
            if (result.modelCalls() != operations
                    || result.toolCalls() != (scenario.equals("mixed") ? operations : 0)) {
                throw new AssertionError("实际业务调用次数与计划不一致");
            }
            int constructors = AgentBenchmarkDetector.CONSTRUCTIONS.get();
            if (constructors != (mode.equals("plugin") ? 1 : 0)
                    || (mode.equals("plugin") && result.pluginChecks() < 2 * operations)) {
                throw new AssertionError("插件实例复用或实际检查次数不符合预期");
            }
            Arrays.sort(result.latency());
            Arrays.sort(result.firstByte());
            System.out.printf(
                    Locale.ROOT,
                    "{\"mode\":\"%s\",\"scenario\":\"%s\",\"threads\":%d,\"operations\":%d,"
                            + "\"operationsPerSecond\":%.3f,\"p50Nanos\":%d,\"p95Nanos\":%d,\"p99Nanos\":%d,"
                            + "\"firstByteP95Nanos\":%d,\"elapsedNanos\":%d,\"modelCalls\":%d,\"toolCalls\":%d,"
                            + "\"pluginConstructions\":%d,\"pluginChecks\":%d,\"heapBeforeBytes\":%d,\"heapAfterBytes\":%d,"
                            + "\"gcCount\":%d,\"gcMillis\":%d,\"warmupRounds\":3,\"warmupIterationsPerWorker\":%d}%n",
                    mode,
                    scenario,
                    threads,
                    operations,
                    operations * 1e9 / result.elapsed(),
                    percentile(result.latency(), .50),
                    percentile(result.latency(), .95),
                    percentile(result.latency(), .99),
                    percentile(result.firstByte(), .95),
                    result.elapsed(),
                    result.modelCalls(),
                    result.toolCalls(),
                    constructors,
                    result.pluginChecks(),
                    result.heapBefore(),
                    result.heapAfter(),
                    result.gcCount(),
                    result.gcMillis(),
                    warmup);
        } finally {
            pool.shutdownNow();
        }
    }

    private static Metrics measure(
            java.util.concurrent.ExecutorService pool,
            String scenario,
            int threads,
            int iterations,
            ChatModel model,
            StreamingChatModel stream,
            ChatRequest request,
            DefaultToolExecutor tool,
            ToolExecutionRequest toolRequest,
            String expected)
            throws Exception {
        long[] latency = new long[threads * iterations];
        long[] firstByte = new long[latency.length];
        long models = MODEL_CALLS.get(),
                tools = TOOL_CALLS.get(),
                checks = AgentBenchmarkDetector.CHECKS.get();
        long gcCount = gc(false), gcMillis = gc(true), heapBefore = heap();
        CountDownLatch ready = new CountDownLatch(threads), start = new CountDownLatch(1);
        var futures = new java.util.ArrayList<java.util.concurrent.Future<?>>();
        for (int worker = 0; worker < threads; worker++) {
            int offset = worker * iterations;
            futures.add(
                    pool.submit(
                            () -> {
                                ready.countDown();
                                try {
                                    start.await();
                                    for (int index = 0; index < iterations; index++) {
                                        long began = System.nanoTime();
                                        if (scenario.equals("mixed")) {
                                            if (!expected.equals(
                                                            model.chat(request).aiMessage().text())
                                                    || !expected.equals(
                                                            tool.execute(
                                                                    toolRequest, "benchmark"))) {
                                                throw new AssertionError("业务结果不一致");
                                            }
                                        } else {
                                            AtomicLong first = new AtomicLong();
                                            AtomicLong chars = new AtomicLong();
                                            CountDownLatch completed = new CountDownLatch(1);
                                            java.util.concurrent.atomic.AtomicReference<Throwable>
                                                    failure =
                                                            new java.util.concurrent.atomic
                                                                    .AtomicReference<>();
                                            stream.chat(
                                                    request,
                                                    new StreamingChatResponseHandler() {
                                                        @Override
                                                        public void onPartialResponse(
                                                                String partial) {
                                                            first.compareAndSet(
                                                                    0, System.nanoTime() - began);
                                                            chars.addAndGet(partial.length());
                                                        }

                                                        @Override
                                                        public void onCompleteResponse(
                                                                ChatResponse response) {
                                                            if (!expected.equals(
                                                                    response.aiMessage().text())) {
                                                                failure.set(
                                                                        new AssertionError(
                                                                                "流式最终正文不一致"));
                                                            }
                                                            completed.countDown();
                                                        }

                                                        @Override
                                                        public void onError(Throwable error) {
                                                            failure.set(error);
                                                            completed.countDown();
                                                        }
                                                    });
                                            if (!completed.await(5, TimeUnit.SECONDS)
                                                    || failure.get() != null
                                                    || chars.get() != expected.length()
                                                    || first.get() <= 0) {
                                                throw new AssertionError("流式失败或内容丢失");
                                            }
                                            firstByte[offset + index] = first.get();
                                        }
                                        latency[offset + index] = System.nanoTime() - began;
                                    }
                                } catch (InterruptedException interrupted) {
                                    Thread.currentThread().interrupt();
                                    throw new IllegalStateException("探针线程中断");
                                }
                            }));
        }
        if (!ready.await(5, TimeUnit.SECONDS)) {
            start.countDown();
            throw new AssertionError("工作线程未就绪");
        }
        long began = System.nanoTime();
        start.countDown();
        for (var future : futures) {
            future.get(180, TimeUnit.SECONDS);
        }
        long elapsed = System.nanoTime() - began;
        return new Metrics(
                latency,
                firstByte,
                elapsed,
                gc(false) - gcCount,
                gc(true) - gcMillis,
                heapBefore,
                heap(),
                MODEL_CALLS.get() - models,
                TOOL_CALLS.get() - tools,
                AgentBenchmarkDetector.CHECKS.get() - checks);
    }

    private static long percentile(long[] values, double percentile) {
        return values[(int) Math.ceil(values.length * percentile) - 1];
    }

    private static long heap() {
        return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
    }

    private static long gc(boolean duration) {
        return ManagementFactory.getGarbageCollectorMXBeans().stream()
                .mapToLong(
                        bean ->
                                Math.max(
                                        0,
                                        duration
                                                ? bean.getCollectionTime()
                                                : bean.getCollectionCount()))
                .sum();
    }
}
