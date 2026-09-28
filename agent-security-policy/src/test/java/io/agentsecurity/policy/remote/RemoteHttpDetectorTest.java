package io.agentsecurity.policy.remote;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import io.agentsecurity.core.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** 真实 HTTP 的闭合协议、资源边界和故障拒绝测试；不调用外部检测服务。 */
class RemoteHttpDetectorTest {
    private static final HttpClient CLIENT =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
    private final SecurityEvent event =
            new SecurityEvent(
                    java.util.UUID.randomUUID(),
                    SecurityEvent.Phase.MODEL_INPUT,
                    "secret-operation",
                    "secret-prompt",
                    SecurityContext.authenticated(
                            "secret-tenant", "secret-user", Set.of("secret-permission")));
    private final AtomicInteger requests = new AtomicInteger();
    private final AtomicReference<String> received = new AtomicReference<>();
    private final AtomicReference<String> auth = new AtomicReference<>();
    private final CountDownLatch entered = new CountDownLatch(1);
    private final CountDownLatch release = new CountDownLatch(1);
    private volatile String mode = "allow";
    private HttpServer server;
    private ExecutorService handlers;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        handlers = Executors.newFixedThreadPool(2);
        server.setExecutor(handlers);
        server.createContext(
                "/detect",
                exchange -> {
                    requests.incrementAndGet();
                    received.set(
                            new String(
                                    exchange.getRequestBody().readAllBytes(),
                                    StandardCharsets.UTF_8));
                    auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
                    String body = reply("ALLOW");
                    int status = 200;
                    String type = "application/json";
                    switch (mode) {
                        case "deny" -> body = reply("DENY");
                        case "auth" -> status = 401;
                        case "forbidden" -> status = 403;
                        case "unavailable" -> status = 503;
                        case "redirect" -> {
                            status = 307;
                            exchange.getResponseHeaders().set("Location", "/detect");
                        }
                        case "empty" -> body = "{}";
                        case "malformed" -> body = "secret-server-error";
                        case "duplicate" ->
                                body =
                                        body.replace(
                                                "\"decision\":",
                                                "\"decision\":\"DENY\",\"decision\":");
                        case "wrong-event" ->
                                body =
                                        body.replace(
                                                event.id().toString(),
                                                java.util.UUID.randomUUID().toString());
                        case "wrong-version" -> body = body.replace("policy-v1", "policy-v2");
                        case "wrong-schema" ->
                                body =
                                        body.replace(
                                                "\"schemaVersion\":1", "\"schemaVersion\":\"1\"");
                        case "unknown-field" -> body = body.replace("{", "{\"extra\":true,");
                        case "trailing" -> body += "{}";
                        case "unknown-verdict" -> body = reply("MAYBE");
                        case "wrong-type" -> type = "text/html";
                        case "oversize" -> body = " ".repeat(17000) + body;
                        case "stall", "hold" -> {
                            exchange.getResponseHeaders().set("Content-Type", type);
                            exchange.sendResponseHeaders(200, 1000);
                            exchange.getResponseBody().write('{');
                            exchange.getResponseBody().flush();
                            entered.countDown();
                            try {
                                release.await(5, TimeUnit.SECONDS);
                            } catch (InterruptedException stopped) {
                                Thread.currentThread().interrupt();
                            } finally {
                                exchange.close();
                            }
                            return;
                        }
                        default -> {}
                    }
                    exchange.getResponseHeaders().set("Content-Type", type);
                    byte[] bytes =
                            mode.equals("invalid-utf8")
                                    ? new byte[] {(byte) 0xff}
                                    : body.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(status, bytes.length);
                    try (exchange) {
                        exchange.getResponseBody().write(bytes);
                    }
                });
        server.start();
    }

    @AfterEach
    void stop() {
        release.countDown();
        server.stop(0);
        handlers.shutdownNow();
    }

    private String reply(String decision) {
        return "{\"schemaVersion\":1,\"eventId\":\""
                + event.id()
                + "\",\"policyVersion\":\"policy-v1\",\"decision\":\""
                + decision
                + "\"}";
    }

    private RemoteDetectorSettings settings(Duration timeout, int bytes) {
        return new RemoteDetectorSettings(
                URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/detect"),
                timeout,
                1,
                bytes,
                "policy-v1",
                Set.of(SecurityEvent.Phase.MODEL_INPUT));
    }

    private RemoteHttpDetector detector(Duration timeout) {
        return new RemoteHttpDetector(
                CLIENT,
                settings(timeout, 4096),
                Map.of("Authorization", "Bearer fixture-token"),
                e -> "minimized");
    }

    @Test
    void allowUsesOnlyExplicitContentAndAuthentication() {
        assertTrue(detector(Duration.ofSeconds(2)).evaluate(event).allowed());
        assertEquals("Bearer fixture-token", auth.get());
        assertTrue(received.get().contains("minimized"));
        assertFalse(received.get().contains("secret-"));
        assertFalse(received.get().contains("fixture-token"));
        assertEquals(1, requests.get());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "deny",
                "auth",
                "forbidden",
                "unavailable",
                "redirect",
                "empty",
                "malformed",
                "duplicate",
                "wrong-event",
                "wrong-version",
                "wrong-schema",
                "unknown-field",
                "trailing",
                "unknown-verdict",
                "wrong-type",
                "invalid-utf8",
                "oversize"
            })
    void unsafeResponsesNeverReachProtectedOperation(String scenario) {
        mode = scenario;
        var effects = new AtomicInteger();
        try (var engine =
                new PolicyEngine(
                        List.of(detector(Duration.ofSeconds(2))),
                        (e, d) -> {},
                        new DetectionLimits(Duration.ofSeconds(3), 1))) {
            var denied =
                    assertThrows(
                            SecurityBlockedException.class,
                            () -> {
                                engine.check(event);
                                effects.incrementAndGet();
                            });
            assertTrue(
                    denied.ruleId().equals("remote-denied")
                            || denied.ruleId().startsWith("detector-remote-"));
            String expected =
                    switch (scenario) {
                        case "deny" -> "remote-denied";
                        case "auth", "forbidden" -> "detector-remote-auth";
                        case "unavailable", "redirect" -> "detector-remote-http";
                        case "oversize" -> "detector-remote-transport";
                        default -> "detector-remote-protocol";
                    };
            assertEquals(expected, denied.ruleId());
            assertFalse(denied.getMessage().contains("secret"));
            assertEquals(0, effects.get());
            assertEquals(1, requests.get());
        }
    }

    @Test
    void bodyStallIsInsideTotalDeadlineAndSlotCanBeReused() {
        mode = "stall";
        var detector = detector(Duration.ofMillis(300));
        assertTimeoutPreemptively(
                Duration.ofSeconds(2),
                () -> assertEquals("detector-remote-timeout", detector.evaluate(event).ruleId()));
        assertEquals(0, entered.getCount(), "Must exercise a stalled response body");
        release.countDown();
        mode = "allow";
        assertTrue(detector.evaluate(event).allowed());
    }

    @Test
    void capacityRejectsWithoutAnotherHttpRequest() throws Exception {
        mode = "hold";
        var detector = detector(Duration.ofSeconds(2));
        var callers = Executors.newSingleThreadExecutor();
        try {
            var pending = callers.submit(() -> detector.evaluate(event));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            assertEquals("detector-remote-capacity", detector.evaluate(event).ruleId());
            assertEquals(1, requests.get());
            release.countDown();
            assertFalse(pending.get(3, TimeUnit.SECONDS).allowed());
        } finally {
            release.countDown();
            callers.shutdownNow();
        }
    }

    @Test
    void excludedPhaseDoesNotSendAndUnboundedOrBrokenContentFailsClosed() {
        var detector = detector(Duration.ofSeconds(2));
        assertTrue(
                detector.evaluate(
                                new SecurityEvent(
                                        SecurityEvent.Phase.MODEL_OUTPUT, "operation", "secret"))
                        .allowed());
        var large =
                new RemoteHttpDetector(
                        CLIENT,
                        settings(Duration.ofSeconds(2), 1024),
                        Map.of(),
                        e -> "\n".repeat(900));
        assertEquals("detector-remote-request", large.evaluate(event).ruleId());
        var broken =
                new RemoteHttpDetector(
                        CLIENT,
                        settings(Duration.ofSeconds(2), 1024),
                        Map.of(),
                        e -> {
                            throw new IllegalArgumentException("secret");
                        });
        assertEquals("detector-remote-request", broken.evaluate(event).ruleId());
        assertEquals(0, requests.get());
    }

    @Test
    void interruptedCallerKeepsFlagAndDoesNotSend() {
        Thread.currentThread().interrupt();
        try {
            assertEquals(
                    "detector-remote-interrupted",
                    detector(Duration.ofSeconds(2)).evaluate(event).ruleId());
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(0, requests.get());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void rejectsUnsafeConfigurationAndHeaders() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new RemoteDetectorSettings(
                                URI.create("http://example.com/detect"),
                                Duration.ofSeconds(1),
                                1,
                                4096,
                                "v1",
                                Set.of(SecurityEvent.Phase.MODEL_INPUT)));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new RemoteHttpDetector(
                                HttpClient.newBuilder()
                                        .followRedirects(HttpClient.Redirect.ALWAYS)
                                        .build(),
                                settings(Duration.ofSeconds(1), 4096),
                                Map.of(),
                                e -> ""));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new RemoteHttpDetector(
                                CLIENT,
                                settings(Duration.ofSeconds(1), 4096),
                                Map.of("Authorization", "secret\nheader"),
                                e -> ""));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new RemoteHttpDetector(
                                CLIENT,
                                settings(Duration.ofSeconds(1), 4096),
                                Map.of("Host", "example.com"),
                                e -> ""));
    }
}
