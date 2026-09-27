package io.agentsecurity.telemetry;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import io.agentsecurity.core.*;
import io.agentsecurity.core.telemetry.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** 本机协议测试覆盖真实请求、响应故障和导出器资源边界。 */
class ExportTest {
    private static final HttpClient CLIENT =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();

    private SecurityTelemetry telemetry(int size) {
        var telemetry = new SecurityTelemetry(4, 1);
        for (int i = 0; i < size; i++) {
            telemetry.record(
                    new SecurityEvent(
                            SecurityEvent.Phase.TOOL_INPUT, "private-tool", "private-text"),
                    SecurityTelemetry.Outcome.ALLOW,
                    2000000);
        }
        return telemetry;
    }

    private OtlpLogExporter exporter(
            SecurityTelemetry telemetry, HttpServer server, Duration timeout) {
        return new OtlpLogExporter(
                telemetry,
                CLIENT,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/logs"),
                "test-service",
                Map.of("Authorization", "Bearer test-token"),
                Duration.ofMillis(10),
                timeout,
                2,
                3);
    }

    private HttpServer server(com.sun.net.httpserver.HttpHandler handler) throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/logs", handler);
        server.start();
        return server;
    }

    private static void await(BooleanSupplier condition) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertTrue(condition.getAsBoolean());
    }

    @Test
    void prometheusCumulativeBucketsAndNoSensitiveLabels() {
        var telemetry = telemetry(2);
        String metrics = PrometheusMetrics.render(telemetry, null);
        assertTrue(metrics.contains("# TYPE agent_security_check_duration_seconds histogram\n"));
        assertTrue(metrics.contains("outcome=\"ALLOW\",le=\"0.001\"} 0\n"));
        assertTrue(metrics.contains("outcome=\"ALLOW\",le=\"0.01\"} 2\n"));
        assertTrue(metrics.contains("outcome=\"ALLOW\",le=\"+Inf\"} 2\n"));
        assertTrue(
                metrics.contains(
                        "agent_security_check_duration_seconds_sum{phase=\"TOOL_INPUT\",outcome=\"ALLOW\"} 0.004\n"));
        assertFalse(metrics.contains("private"));
        assertTrue(
                metrics.lastIndexOf("agent_security_events_total{")
                        < metrics.indexOf("# TYPE agent_security_check_duration_seconds"));
        assertEquals(2, telemetry.snapshot().queued());
    }

    @Test
    void responseParserRejectsMalformedOrImpossibleCounts() throws Exception {
        assertEquals(0, OtlpJson.rejected("{}".getBytes(StandardCharsets.UTF_8), 2));
        assertEquals(
                1,
                OtlpJson.rejected(
                        "{\"partialSuccess\":{\"rejectedLogRecords\":\"1\"}}"
                                .getBytes(StandardCharsets.UTF_8),
                        2));
        for (var body :
                List.of(
                        "",
                        "{}{}",
                        "{",
                        "{\"partialSuccess\":{\"rejectedLogRecords\":3}}",
                        "{\"partialSuccess\":{\"rejectedLogRecords\":-1}}",
                        "{\"partialSuccess\":{},\"partialSuccess\":{}}")) {
            assertThrows(
                    java.io.IOException.class,
                    () -> OtlpJson.rejected(body.getBytes(StandardCharsets.UTF_8), 2));
        }
    }

    @Test
    void exportsJsonWithAuthenticationAndPrivacy() throws Exception {
        var body = new AtomicReference<String>();
        var auth = new AtomicReference<String>();
        var server =
                server(
                        exchange -> {
                            auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
                            body.set(
                                    new String(
                                            exchange.getRequestBody().readAllBytes(),
                                            StandardCharsets.UTF_8));
                            exchange.getResponseHeaders().set("Content-Type", "application/json");
                            exchange.sendResponseHeaders(200, 2);
                            exchange.getResponseBody().write("{}".getBytes(StandardCharsets.UTF_8));
                            exchange.close();
                        });
        try (var exporter = exporter(telemetry(2), server, Duration.ofSeconds(1))) {
            await(() -> exporter.health().accepted() == 2);
            assertEquals("Bearer test-token", auth.get());
            assertTrue(body.get().contains("resourceLogs"));
            assertTrue(body.get().contains("timeUnixNano\":\""));
            assertTrue(body.get().contains("security.event.id"));
            assertFalse(body.get().contains("private"));
            assertEquals(0, exporter.health().dropped());
            assertEquals(1, exporter.health().attempts());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void transientFailureRetriesSameBatchThenSucceeds() throws Exception {
        var requests = new AtomicInteger();
        var first = new AtomicReference<String>();
        var same = new AtomicReference<Boolean>(true);
        var server =
                server(
                        exchange -> {
                            var body =
                                    new String(
                                            exchange.getRequestBody().readAllBytes(),
                                            StandardCharsets.UTF_8);
                            if (first.get() == null) {
                                first.set(body);
                            } else {
                                same.set(first.get().equals(body));
                            }
                            int status = requests.incrementAndGet() == 1 ? 503 : 200;
                            exchange.getResponseHeaders().set("Content-Type", "application/json");
                            exchange.getResponseHeaders().set("Retry-After", "0");
                            exchange.sendResponseHeaders(status, 2);
                            exchange.getResponseBody().write("{}".getBytes(StandardCharsets.UTF_8));
                            exchange.close();
                        });
        try (var exporter = exporter(telemetry(2), server, Duration.ofSeconds(1))) {
            await(() -> exporter.health().accepted() == 2);
            assertTrue(same.get());
            assertEquals(2, exporter.health().attempts());
            assertEquals(1, exporter.health().failures());
        } finally {
            server.stop(0);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 401, 302, 500})
    void permanentFailuresAndRedirectsAreNotRetried(int status) throws Exception {
        var server =
                server(
                        exchange -> {
                            exchange.getRequestBody().readAllBytes();
                            exchange.sendResponseHeaders(status, -1);
                            exchange.close();
                        });
        try (var exporter = exporter(telemetry(2), server, Duration.ofSeconds(1))) {
            await(() -> exporter.health().dropped() == 2);
            assertEquals(1, exporter.health().attempts());
            assertEquals(0, exporter.health().accepted());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void partialSuccessDoesNotResendAcceptedRecords() throws Exception {
        var server =
                server(
                        exchange -> {
                            exchange.getRequestBody().readAllBytes();
                            byte[] body =
                                    "{\"partialSuccess\":{\"rejectedLogRecords\":\"1\",\"errorMessage\":\"private diagnostic\"}}"
                                            .getBytes(StandardCharsets.UTF_8);
                            exchange.getResponseHeaders().set("Content-Type", "application/json");
                            exchange.sendResponseHeaders(200, body.length);
                            exchange.getResponseBody().write(body);
                            exchange.close();
                        });
        try (var exporter = exporter(telemetry(2), server, Duration.ofSeconds(1))) {
            await(() -> exporter.health().pending() == 0 && exporter.health().accepted() == 1);
            assertEquals(1, exporter.health().dropped());
            assertEquals(1, exporter.health().attempts());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void oversizedResponseIsDroppedWithoutRetry() throws Exception {
        var server =
                server(
                        exchange -> {
                            exchange.getRequestBody().readAllBytes();
                            exchange.getResponseHeaders().set("Content-Type", "application/json");
                            exchange.sendResponseHeaders(200, 20000);
                            try {
                                exchange.getResponseBody().write(new byte[20000]);
                            } finally {
                                exchange.close();
                            }
                        });
        try (var exporter = exporter(telemetry(2), server, Duration.ofSeconds(1))) {
            await(() -> exporter.health().dropped() == 2);
            assertEquals(1, exporter.health().attempts());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void retryBudgetExhaustionAndQueueBoundDoNotChangeSecurityDecisions() throws Exception {
        var server =
                server(
                        exchange -> {
                            exchange.getRequestBody().readAllBytes();
                            exchange.sendResponseHeaders(503, -1);
                            exchange.close();
                        });
        var telemetry = telemetry(2);
        try (var exporter = exporter(telemetry, server, Duration.ofSeconds(1))) {
            await(() -> exporter.health().dropped() == 2);
            assertEquals(3, exporter.health().attempts());
            assertTrue(
                    PrometheusMetrics.render(telemetry, exporter)
                            .contains("agent_security_export_failures_total 3"));
            exporter.close();
            try (var engine =
                    new PolicyEngine(
                            List.of(e -> Decision.deny("denied")),
                            (e, d) -> {},
                            DetectionLimits.defaults(),
                            telemetry)) {
                for (int i = 0; i < 20; i++) {
                    assertThrows(
                            SecurityBlockedException.class,
                            () ->
                                    engine.check(
                                            new SecurityEvent(
                                                    SecurityEvent.Phase.TOOL_INPUT, "lookup", "")));
                }
            }
            assertTrue(telemetry.snapshot().queued() <= 4);
            assertTrue(telemetry.snapshot().dropped() >= 16);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void responseBodyStallHasDeadlineAndCloseCancelsPending() throws Exception {
        var server =
                server(
                        exchange -> {
                            exchange.getRequestBody().readAllBytes();
                            exchange.getResponseHeaders().set("Content-Type", "application/json");
                            exchange.sendResponseHeaders(200, 20);
                            exchange.getResponseBody().write('{');
                            exchange.getResponseBody().flush();
                            try {
                                Thread.sleep(400);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                            }
                            exchange.close();
                        });
        try (var exporter = exporter(telemetry(2), server, Duration.ofMillis(100))) {
            await(() -> exporter.health().timeouts() >= 1);
            long start = System.nanoTime();
            exporter.close();
            assertTrue(System.nanoTime() - start < Duration.ofMillis(100).toNanos());
            await(() -> exporter.health().pending() == 0);
            assertEquals(2, exporter.health().dropped());
        } finally {
            server.stop(0);
        }
    }
}
