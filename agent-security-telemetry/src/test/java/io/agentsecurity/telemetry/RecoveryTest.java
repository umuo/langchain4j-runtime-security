package io.agentsecurity.telemetry;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import io.agentsecurity.core.*;
import io.agentsecurity.core.telemetry.SecurityTelemetry;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

/** 短时故障注入验证恢复和计数；不冒充真实 Collector 或长期网络稳定性测试。 */
class RecoveryTest {
    private static final HttpClient CLIENT = HttpClient.newHttpClient();

    private OtlpLogExporter exporter(SecurityTelemetry telemetry, HttpServer server) {
        return new OtlpLogExporter(
                telemetry,
                CLIENT,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/logs"),
                "recovery",
                Map.of(),
                Duration.ofMillis(10),
                Duration.ofSeconds(1),
                8,
                1);
    }

    private void record(SecurityTelemetry telemetry) {
        telemetry.record(
                new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "lookup", ""),
                SecurityTelemetry.Outcome.ALLOW,
                1);
    }

    @Test
    void outageBackpressureAndRecoveryPreserveAccountingAndPolicy() throws Exception {
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
        var telemetry = new SecurityTelemetry(32, 1);
        try (var exporter = exporter(telemetry, server);
                var engine =
                        new PolicyEngine(
                                List.of(e -> Decision.deny("denied")),
                                (e, d) -> {},
                                DetectionLimits.defaults(),
                                telemetry)) {
            // 持续生产超过队列容量，观察导出故障时资源及安全决策。
            for (int i = 0; i < 1000; i++) {
                record(telemetry);
                assertTrue(telemetry.snapshot().queued() <= 32);
                assertTrue(exporter.health().pending() <= 8);
                if (i % 20 == 0) {
                    Thread.sleep(10);
                }
            }
            assertThrows(
                    SecurityBlockedException.class,
                    () ->
                            engine.check(
                                    new SecurityEvent(
                                            SecurityEvent.Phase.TOOL_INPUT, "lookup", "")));
            assertTrue(exporter.awaitDrained(Duration.ofSeconds(5)));
            assertEquals(0, exporter.health().accepted());
            assertTrue(exporter.health().failures() > 0);
            assertTrue(telemetry.snapshot().dropped() > 0);
            healthy.set(true);
            record(telemetry);
            assertTrue(exporter.awaitDrained(Duration.ofSeconds(5)));
            assertEquals(1, exporter.health().accepted());
            assertTrue(exporter.isRunning());
            long recorded =
                    telemetry.snapshot().metrics().stream()
                            .mapToLong(SecurityTelemetry.Metric::count)
                            .sum();
            assertEquals(1002, recorded);
            assertEquals(
                    recorded,
                    exporter.health().accepted()
                            + exporter.health().dropped()
                            + telemetry.snapshot().dropped());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void drainedWaitIncludesInFlightRequestAndHonorsDeadline() throws Exception {
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(
                "/v1/logs",
                exchange -> {
                    exchange.getRequestBody().readAllBytes();
                    entered.countDown();
                    try {
                        release.await(2, TimeUnit.SECONDS);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, 2);
                    exchange.getResponseBody().write(new byte[] {'{', '}'});
                    exchange.close();
                });
        server.start();
        var telemetry = new SecurityTelemetry(32, 1);
        record(telemetry);
        try (var exporter = exporter(telemetry, server)) {
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            assertEquals(0, telemetry.snapshot().queued());
            assertEquals(1, exporter.health().pending());
            assertFalse(exporter.awaitDrained(Duration.ofMillis(30)));
            release.countDown();
            assertTrue(exporter.awaitDrained(Duration.ofSeconds(2)));
            assertEquals(1, exporter.health().accepted());
            exporter.close();
            assertFalse(exporter.isRunning());
            record(telemetry);
            assertFalse(exporter.awaitDrained(Duration.ofSeconds(1)));
            assertThrows(
                    IllegalArgumentException.class, () -> exporter.awaitDrained(Duration.ZERO));
            assertThrows(
                    IllegalArgumentException.class,
                    () -> exporter.awaitDrained(Duration.ofSeconds(31)));
        } finally {
            release.countDown();
            server.stop(0);
        }
    }
}
