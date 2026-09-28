package io.agentsecurity.fixture;

import com.fasterxml.jackson.core.JsonFactory;
import com.sun.net.httpserver.HttpServer;
import dev.langchain4j.service.AiServices;
import io.agentsecurity.core.SecurityEvent;
import io.agentsecurity.policy.remote.RemoteDetectorSettings;
import io.agentsecurity.policy.remote.RemoteHttpDetector;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/** 真实 Boot SPI 到本机检测服务，检查模型副作用发生前的远程拒绝。 */
final class RemoteFixture {
    static void run(String scenario) throws Exception {
        var requests = new AtomicInteger();
        Set<String> eventIds = java.util.concurrent.ConcurrentHashMap.newKeySet();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(
                "/detect",
                exchange -> {
                    requests.incrementAndGet();
                    String id = null;
                    try (var json = new JsonFactory().createParser(exchange.getRequestBody())) {
                        while (json.nextToken() != null) {
                            if (json.currentToken()
                                            == com.fasterxml.jackson.core.JsonToken.FIELD_NAME
                                    && json.currentName().equals("eventId")) {
                                id = json.nextTextValue();
                            }
                        }
                    }
                    eventIds.add(java.util.UUID.fromString(id).toString());
                    boolean authenticated =
                            "Bearer fixture-auth-token"
                                    .equals(exchange.getRequestHeaders().getFirst("Authorization"));
                    String decision = scenario.equals("remote-denied") ? "DENY" : "ALLOW";
                    String response =
                            scenario.equals("remote-malformed")
                                    ? "{}"
                                    : "{\"schemaVersion\":1,\"eventId\":\""
                                            + java.util.UUID.fromString(id)
                                            + "\",\"policyVersion\":\"fixture-v1\",\"decision\":\""
                                            + decision
                                            + "\"}";
                    byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(
                            !authenticated || scenario.equals("remote-auth") ? 401 : 200,
                            bytes.length);
                    try (exchange) {
                        exchange.getResponseBody().write(bytes);
                    }
                });
        server.start();
        try {
            FixtureDetector.remote =
                    new RemoteHttpDetector(
                            HttpClient.newHttpClient(),
                            new RemoteDetectorSettings(
                                    URI.create(
                                            "http://127.0.0.1:"
                                                    + server.getAddress().getPort()
                                                    + "/detect"),
                                    Duration.ofSeconds(2),
                                    1,
                                    4096,
                                    "fixture-v1",
                                    Set.of(SecurityEvent.Phase.MODEL_INPUT)),
                            Map.of("Authorization", "Bearer fixture-auth-token"),
                            event -> "minimized-fixture");
            AiServices.builder(BootFixture.Assistant.class)
                    .chatModel(new BootFixture.MockModel(null))
                    .build()
                    .chat("REMOTE_REQUEST_SECRET");
        } finally {
            FixtureDetector.remote = null;
            server.stop(0);
            System.out.println("REMOTE_REQUESTS=" + requests.get());
            System.out.println("REMOTE_UNIQUE_EVENTS=" + eventIds.size());
        }
    }
}
