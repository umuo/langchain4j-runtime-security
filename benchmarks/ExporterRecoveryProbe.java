import com.sun.net.httpserver.HttpServer;
import io.agentsecurity.core.SecurityEvent;
import io.agentsecurity.core.telemetry.SecurityTelemetry;
import io.agentsecurity.telemetry.OtlpLogExporter;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/** 本机 503 到恢复的持续探针；只发送合成事件，不访问外部服务。 */
public final class ExporterRecoveryProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("outageSeconds recoverySeconds required");
        }
        int outage = Integer.parseInt(args[0]);
        int recovery = Integer.parseInt(args[1]);
        if (outage < 1
                || recovery < 1
                || outage > 3000
                || recovery > 600
                || outage + recovery > 3600) {
            throw new IllegalArgumentException("Invalid probe duration");
        }
        var healthy = new AtomicBoolean();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(
                "/v1/logs",
                exchange -> {
                    exchange.getRequestBody().readAllBytes();
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(healthy.get() ? 200 : 503, 2);
                    exchange.getResponseBody().write(new byte[] {'{', '}'});
                    exchange.close();
                });
        server.start();
        var telemetry = new SecurityTelemetry(128, 1);
        var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
        long generated = 0;
        long maxQueued = 0;
        long maxPending = 0;
        long maxHeap = 0;
        long maxThreads = 0;
        long start = System.nanoTime();
        long firstAcceptedAfterRecovery = -1;
        try (var exporter =
                new OtlpLogExporter(
                        telemetry,
                        client,
                        URI.create(
                                "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/logs"),
                        "local-probe",
                        Map.of(),
                        Duration.ofMillis(10),
                        Duration.ofSeconds(1),
                        32,
                        3)) {
            long outageNanos = Duration.ofSeconds(outage).toNanos();
            long totalNanos = Duration.ofSeconds(outage + recovery).toNanos();
            while (System.nanoTime() - start < totalNanos) {
                long elapsed = System.nanoTime() - start;
                if (elapsed >= outageNanos) {
                    healthy.set(true);
                }
                telemetry.record(
                        new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "synthetic", ""),
                        SecurityTelemetry.Outcome.ALLOW,
                        1);
                generated++;
                var state = exporter.health();
                maxQueued = Math.max(maxQueued, telemetry.queuedRecords());
                maxPending = Math.max(maxPending, state.pending());
                if (maxQueued > 128 || maxPending > 32) {
                    throw new IllegalStateException("Queue bound violated");
                }
                if (healthy.get() && state.accepted() > 0 && firstAcceptedAfterRecovery < 0) {
                    firstAcceptedAfterRecovery = elapsed - outageNanos;
                }
                // 固定采样间隔的进程级观察，不等同于 RSS 或真实峰值。
                if (generated % 20 == 0) {
                    maxHeap =
                            Math.max(
                                    maxHeap,
                                    ManagementFactory.getMemoryMXBean()
                                            .getHeapMemoryUsage()
                                            .getUsed());
                    maxThreads =
                            Math.max(
                                    maxThreads,
                                    ManagementFactory.getThreadMXBean().getThreadCount());
                }
                Thread.sleep(5);
            }
            if (!exporter.awaitDrained(Duration.ofSeconds(10))) {
                throw new IllegalStateException("Drain timed out");
            }
            var health = exporter.health();
            long queueDropped = telemetry.snapshot().dropped();
            if (health.accepted() == 0
                    || health.failures() == 0
                    || generated != health.accepted() + health.dropped() + queueDropped) {
                throw new IllegalStateException("Recovery or accounting failed");
            }
            System.out.printf(
                    java.util.Locale.ROOT,
                    "{\"outageSeconds\":%d,\"recoverySeconds\":%d,\"generated\":%d,"
                            + "\"accepted\":%d,\"exportDropped\":%d,\"queueDropped\":%d,"
                            + "\"attempts\":%d,\"failures\":%d,\"maxQueued\":%d,\"maxPending\":%d,"
                            + "\"sampledMaxHeapBytes\":%d,\"sampledMaxJvmThreads\":%d,"
                            + "\"firstAcceptedAfterRecoveryNanos\":%d,\"drained\":true}%n",
                    outage,
                    recovery,
                    generated,
                    health.accepted(),
                    health.dropped(),
                    queueDropped,
                    health.attempts(),
                    health.failures(),
                    maxQueued,
                    maxPending,
                    maxHeap,
                    maxThreads,
                    firstAcceptedAfterRecovery);
        } finally {
            server.stop(0);
        }
    }
}
