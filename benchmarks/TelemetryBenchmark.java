import io.agentsecurity.core.DetectionLimits;
import io.agentsecurity.core.PolicyEngine;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityEvent;
import io.agentsecurity.core.telemetry.SecurityTelemetry;
import java.lang.management.ManagementFactory;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** 本机诊断基线，不替代 JMH 或生产负载验收；只测引擎及遥测，排除网络和真实审计。 */
public final class TelemetryBenchmark {
    private record Result(
            long operations,
            long elapsed,
            long p50,
            long p95,
            long p99,
            long maximum,
            long recorded,
            long consumed,
            long dropped,
            long queued,
            long heapBefore,
            long heapAfter,
            long gcCount,
            long gcMillis) {}

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException("mode threads iterations capacity required");
        }
        String mode = args[0];
        int threads = Integer.parseInt(args[1]);
        int iterations = Integer.parseInt(args[2]);
        int capacity = Integer.parseInt(args[3]);
        if (!Set.of("disabled", "draining", "stalled").contains(mode)
                || threads < 1
                || threads > 32
                || iterations < 100
                || (long) threads * iterations > 1000000
                || capacity < 1
                || capacity > 65536) {
            throw new IllegalArgumentException("Invalid benchmark limits");
        }
        // 同一 JVM 内先对相同场景预热，正式测量使用新收集器，避免暖机数据进入计数。
        for (int warmup = 0; warmup < 3; warmup++) {
            measure(mode, threads, Math.min(iterations, 100000), capacity);
        }
        var result = measure(mode, threads, iterations, capacity);
        System.out.printf(
                java.util.Locale.ROOT,
                "{\"mode\":\"%s\",\"threads\":%d,\"capacity\":%d,\"operations\":%d,"
                        + "\"elapsedNanos\":%d,\"operationsPerSecond\":%.3f,"
                        + "\"p50Nanos\":%d,\"p95Nanos\":%d,\"p99Nanos\":%d,\"maxNanos\":%d,"
                        + "\"recorded\":%d,\"consumed\":%d,\"dropped\":%d,\"queued\":%d,"
                        + "\"heapBeforeBytes\":%d,\"heapAfterBytes\":%d,\"gcCount\":%d,\"gcMillis\":%d}%n",
                mode,
                threads,
                capacity,
                result.operations(),
                result.elapsed(),
                result.operations() * 1e9 / result.elapsed(),
                result.p50(),
                result.p95(),
                result.p99(),
                result.maximum(),
                result.recorded(),
                result.consumed(),
                result.dropped(),
                result.queued(),
                result.heapBefore(),
                result.heapAfter(),
                result.gcCount(),
                result.gcMillis());
    }

    private static Result measure(String mode, int threads, int iterations, int capacity)
            throws Exception {
        var telemetry =
                mode.equals("disabled")
                        ? SecurityTelemetry.disabled()
                        : new SecurityTelemetry(capacity, 1);
        var consuming = new AtomicBoolean(true);
        var consumed = new AtomicLong();
        var error = new AtomicReference<Throwable>();
        Thread consumer = null;
        if (mode.equals("draining")) {
            consumer =
                    new Thread(
                            () -> {
                                while (consuming.get()) {
                                    int count = telemetry.drain(256).size();
                                    consumed.addAndGet(count);
                                    if (count == 0) {
                                        Thread.yield();
                                    }
                                }
                            },
                            "benchmark-consumer");
            consumer.setDaemon(true);
            consumer.start();
        }
        long[] samples = new long[threads * iterations];
        var ready = new CountDownLatch(threads);
        var start = new CountDownLatch(1);
        var done = new CountDownLatch(threads);
        var event =
                new SecurityEvent(
                        UUID.randomUUID(),
                        SecurityEvent.Phase.TOOL_INPUT,
                        "lookup",
                        "",
                        SecurityContext.authenticated("benchmark", "benchmark", Set.of()));
        try (var engine =
                new PolicyEngine(List.of(), (e, d) -> {}, DetectionLimits.defaults(), telemetry)) {
            for (int worker = 0; worker < threads; worker++) {
                final int offset = worker * iterations;
                var thread =
                        new Thread(
                                () -> {
                                    ready.countDown();
                                    try {
                                        start.await();
                                        for (int i = 0; i < iterations; i++) {
                                            long begin = System.nanoTime();
                                            engine.check(event);
                                            samples[offset + i] = System.nanoTime() - begin;
                                        }
                                    } catch (Throwable failed) {
                                        error.compareAndSet(null, failed);
                                    } finally {
                                        done.countDown();
                                    }
                                },
                                "benchmark-worker-" + worker);
                thread.setDaemon(true);
                thread.start();
            }
            if (!ready.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Workers not ready");
            }
            long heapBefore = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
            long gcCount = gc(false);
            long gcMillis = gc(true);
            long begin = System.nanoTime();
            start.countDown();
            if (!done.await(60, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Benchmark timeout");
            }
            long elapsed = System.nanoTime() - begin;
            long heapAfter = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
            gcCount = gc(false) - gcCount;
            gcMillis = gc(true) - gcMillis;
            consuming.set(false);
            if (consumer != null) {
                consumer.join(1000);
            }
            if (consumer != null && consumer.isAlive()) {
                throw new IllegalStateException("Consumer not stopped");
            }
            if (error.get() != null) {
                throw new IllegalStateException("Worker failed", error.get());
            }
            var snapshot = telemetry.snapshot();
            long recorded =
                    snapshot.metrics().stream().mapToLong(SecurityTelemetry.Metric::count).sum();
            long operations = (long) threads * iterations;
            if (!mode.equals("disabled")
                    && (recorded != operations
                            || consumed.get() + snapshot.dropped() + snapshot.queued() != operations
                            || snapshot.queued() > capacity)) {
                throw new IllegalStateException("Telemetry accounting or capacity violation");
            }
            Arrays.sort(samples);
            return new Result(
                    operations,
                    elapsed,
                    percentile(samples, .50),
                    percentile(samples, .95),
                    percentile(samples, .99),
                    samples[samples.length - 1],
                    recorded,
                    consumed.get(),
                    snapshot.dropped(),
                    snapshot.queued(),
                    heapBefore,
                    heapAfter,
                    gcCount,
                    gcMillis);
        } finally {
            consuming.set(false);
            start.countDown();
            if (consumer != null) {
                consumer.join(1000);
            }
        }
    }

    private static long percentile(long[] samples, double percentile) {
        return samples[(int) Math.ceil(samples.length * percentile) - 1];
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
