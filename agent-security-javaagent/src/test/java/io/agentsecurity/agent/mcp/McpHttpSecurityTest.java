package io.agentsecurity.agent.mcp;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.SecurityBlockedException;
import java.net.URI;
import java.net.http.*;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class McpHttpSecurityTest {
    private static final String URL = "http://127.0.0.1:12345/mcp";

    @Test
    void rejectsUnsafeTargetsAndRedirectingClientsBeforeNetwork() {
        for (String target :
                new String[] {
                    "http://remote.test/mcp",
                    "http://localhost/mcp",
                    "https://user:secret@remote.test/mcp",
                    "https://remote.test/mcp#fragment",
                    "file:///tmp/a"
                }) {
            assertEquals(
                    "mcp-http-target",
                    assertThrows(
                                    SecurityBlockedException.class,
                                    () -> McpHttpSecurity.endpoint(target))
                            .ruleId());
        }
        assertEquals(
                URI.create("https://remote.test/mcp"),
                McpHttpSecurity.endpoint("https://remote.test/mcp"));
        assertEquals(URI.create("http://[::1]/mcp"), McpHttpSecurity.endpoint("http://[::1]/mcp"));
        assertThrows(
                SecurityBlockedException.class,
                () ->
                        new McpHttpSecurity(
                                URL,
                                HttpClient.newBuilder()
                                        .followRedirects(HttpClient.Redirect.NORMAL)
                                        .build(),
                                new McpResponseLimits.State(1024)));
    }

    @Test
    void requiresSingleValidBearerAndConfigurationIsStrict() {
        var settings = new Properties();
        settings.setProperty("mcp.http.require.bearer", "true");
        McpHttpSecurity.initialize(settings);
        try {
            for (String value :
                    new String[] {
                        "", "Basic secret", "Bearer ", "Bearer x y", "Bearer x".repeat(2000)
                    }) {
                var guard = guard();
                var builder = HttpRequest.newBuilder(URI.create(URL));
                if (!value.isEmpty()) {
                    builder.header("Authorization", value);
                }
                assertEquals(
                        "mcp-http-auth-required",
                        assertThrows(
                                        SecurityBlockedException.class,
                                        () -> guard.check(builder.build()))
                                .ruleId());
            }
            guard().check(request("Bearer opaque-token"));
            var duplicate =
                    HttpRequest.newBuilder(URI.create(URL))
                            .header("Authorization", "Bearer x")
                            .header("authorization", "Bearer y")
                            .build();
            assertThrows(SecurityBlockedException.class, () -> guard().check(duplicate));
        } finally {
            McpHttpSecurity.initialize(new Properties());
        }
        settings.setProperty("mcp.http.require.bearer", "yes");
        assertThrows(IllegalArgumentException.class, () -> McpHttpSecurity.initialize(settings));
    }

    @Test
    void credentialChangesPoisonSharedClientStateWithoutKeepingToken() {
        var state = new McpResponseLimits.State(1024);
        var guard = new McpHttpSecurity(URL, HttpClient.newHttpClient(), state);
        guard.check(request("Bearer token-a"));
        assertEquals(
                "mcp-http-credential-changed",
                assertThrows(
                                SecurityBlockedException.class,
                                () -> guard.check(request("Bearer token-b")))
                        .ruleId());
        assertThrows(SecurityBlockedException.class, state::check);
        guard().check(request("Bearer token-b"));
        var anonymous = guard();
        anonymous.check(HttpRequest.newBuilder(URI.create(URL)).build());
        assertThrows(SecurityBlockedException.class, () -> anonymous.check(request("anonymous")));
    }

    @Test
    void statusFailuresRemainFailedAndAreNotCapacityCounters() {
        for (int code : new int[] {301, 307, 401, 403, 404, 500, 503}) {
            var metrics = new io.agentsecurity.core.health.McpDiagnostics();
            var state = new McpResponseLimits.State(1024, metrics);
            var guard = new McpHttpSecurity(URL, HttpClient.newHttpClient(), state);
            var failure =
                    assertThrows(SecurityBlockedException.class, () -> guard.response(code, null));
            assertNotNull(failure.diagnostic());
            assertEquals(
                    failure.ruleId(),
                    assertThrows(SecurityBlockedException.class, state::check).ruleId());
            assertEquals(0, metrics.snapshot().transportFailures());
        }
        guard().response(200, null);
        guard().response(202, null);
    }

    @Test
    void endpointChangeIsRejectedEvenWithoutAuthorization() {
        var guard = guard();
        assertEquals(
                "mcp-http-target",
                assertThrows(
                                SecurityBlockedException.class,
                                () ->
                                        guard.check(
                                                HttpRequest.newBuilder(URI.create(URL + "?other=1"))
                                                        .build()))
                        .ruleId());
    }

    private static McpHttpSecurity guard() {
        return new McpHttpSecurity(
                URL, HttpClient.newHttpClient(), new McpResponseLimits.State(1024));
    }

    private static HttpRequest request(String value) {
        return HttpRequest.newBuilder(URI.create(URL)).header("Authorization", value).build();
    }
}
