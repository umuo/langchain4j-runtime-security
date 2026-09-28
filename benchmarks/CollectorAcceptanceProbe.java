import com.fasterxml.jackson.core.JsonFactory;
import io.agentsecurity.core.*;
import io.agentsecurity.core.delegation.*;
import io.agentsecurity.core.telemetry.SecurityTelemetry;
import io.agentsecurity.telemetry.OtlpLogExporter;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** 真实 Collector 验收客户端：正常 JDK 证书校验，禁止跳过主机名或信任校验。 */
public final class CollectorAcceptanceProbe {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException("endpoint trustStore clientStore expectedSuccess");
        }
        var builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2));
        if (!args[1].equals("-")) {
            var trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(store(args[1]));
            KeyManagerFactory keys = null;
            if (!args[2].equals("-")) {
                keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keys.init(store(args[2]), "acceptance-only".toCharArray());
            }
            var ssl = SSLContext.getInstance("TLS");
            ssl.init(keys == null ? null : keys.getKeyManagers(), trust.getTrustManagers(), null);
            builder.sslContext(ssl);
        }
        boolean success = Boolean.parseBoolean(args[3]);
        var telemetry = new SecurityTelemetry(256, 1);
        var identity = SecurityContext.authenticated("secret-tenant", "secret-principal", Set.of());
        List<Map<String, String>> events =
                java.util.Collections.synchronizedList(new ArrayList<>());
        java.util.function.BiConsumer<SecurityEvent, Decision> audit =
                (event, decision) -> events.add(expected(event, decision));
        int sideEffects = 0;
        try (var exporter =
                        new OtlpLogExporter(
                                telemetry,
                                builder.build(),
                                URI.create(args[0]),
                                "collector-acceptance",
                                Map.of(),
                                Duration.ofMillis(10),
                                Duration.ofSeconds(2),
                                100,
                                1);
                var engine =
                        new PolicyEngine(
                                List.of(
                                        event ->
                                                event.text().equals("secret-deny")
                                                        ? Decision.deny("acceptance-deny")
                                                        : Decision.allow()),
                                audit,
                                DetectionLimits.defaults(),
                                telemetry)) {
            for (int i = 0; i < 100; i++) {
                boolean deny = i % 2 == 1;
                var event =
                        new SecurityEvent(
                                java.util.UUID.randomUUID(),
                                SecurityEvent.Phase.TOOL_INPUT,
                                "secret-operation",
                                deny ? "secret-deny" : "secret-allow",
                                identity);
                try {
                    engine.check(event);
                    if (deny) {
                        throw new IllegalStateException("Denied operation escaped policy");
                    }
                    sideEffects++;
                } catch (SecurityBlockedException blocked) {
                    if (!deny || !blocked.ruleId().equals("acceptance-deny")) {
                        throw blocked;
                    }
                }
            }
            var grant = AgentGrant.tools(Set.of(), Set.of("secret-operation"));
            try (var runtime =
                    new AgentRuntime(
                            List.of(
                                    new AgentDefinition("parent", grant, Set.of("child")),
                                    new AgentDefinition("child", grant, Set.of())),
                            AgentRuntimeLimits.defaults(),
                            audit,
                            telemetry)) {
                var root = runtime.startRoot("parent", identity, grant, Duration.ofSeconds(30));
                root.call(
                        () -> {
                            var child = runtime.delegate("child", grant, Duration.ofSeconds(20));
                            return child.call(
                                    () -> {
                                        engine.check(
                                                new SecurityEvent(
                                                        SecurityEvent.Phase.TOOL_INPUT,
                                                        "secret-operation",
                                                        "secret-allow"));
                                        return null;
                                    });
                        });
            }
            if (events.size() != 105) {
                throw new IllegalStateException("Missing policy or lifecycle audit events");
            }
            if (!exporter.awaitDrained(Duration.ofSeconds(30))) {
                throw new IllegalStateException("Drain timeout");
            }
            var health = exporter.health();
            if (telemetry.snapshot().dropped() != 0
                    || health.pending() != 0
                    || sideEffects != 50
                    || health.accepted() != (success ? 105 : 0)
                    || health.dropped() != (success ? 0 : 105)
                    || (success ? health.failures() != 0 : health.failures() == 0)) {
                throw new IllegalStateException("Unexpected exporter accounting: " + health);
            }
            try (var json = new JsonFactory().createGenerator(System.out)) {
                json.writeStartObject();
                json.writeNumberField("accepted", health.accepted());
                json.writeNumberField("dropped", health.dropped());
                json.writeNumberField("failures", health.failures());
                json.writeNumberField("allowedSideEffects", sideEffects);
                json.writeArrayFieldStart("expected");
                for (var event : events) {
                    json.writeStartObject();
                    for (var field : event.entrySet()) {
                        json.writeStringField(field.getKey(), field.getValue());
                    }
                    json.writeEndObject();
                }
                json.writeEndArray();
                json.writeEndObject();
            }
        }
    }

    /** 从独立审计通道冻结期望值，避免终止后的可变句柄影响创建事件的断言。 */
    private static Map<String, String> expected(SecurityEvent event, Decision decision) {
        var fields = new java.util.HashMap<String, String>();
        fields.put("security.event.id", event.id().toString());
        fields.put("security.run.id", event.context().runId().toString());
        fields.put("security.phase", event.phase().name());
        fields.put("security.outcome", decision.allowed() ? "ALLOW" : "DENY");
        var invocation = event.context().invocation();
        if (invocation != null) {
            fields.put("security.invocation.id", invocation.invocationId().toString());
            fields.put("security.delegation.depth", Integer.toString(invocation.depth()));
            if (invocation.parentInvocationId() != null) {
                fields.put(
                        "security.parent.invocation.id",
                        invocation.parentInvocationId().toString());
            }
            if (invocation.endReason() != null) {
                fields.put("security.end.reason", invocation.endReason().name());
            }
        }
        return Map.copyOf(fields);
    }

    /** 口令只用于临时测试证书，不作为真实凭据示例。 */
    private static KeyStore store(String path) throws Exception {
        var store = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(Path.of(path))) {
            store.load(input, "acceptance-only".toCharArray());
        }
        return store;
    }
}
