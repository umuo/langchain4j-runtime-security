package io.agentsecurity.agent.mcp;

import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.diagnostics.FailureDiagnostics;
import io.agentsecurity.core.diagnostics.FailureRecord.Stage;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.List;
import java.util.Properties;

/** 官方 HTTP 传输的目标和认证边界；不持有、生成或刷新凭据。 */
public final class McpHttpSecurity {
    private static volatile boolean requireBearer;
    private final URI endpoint;
    private final boolean bearer;
    private final McpResponseLimits.State state;
    private final java.util.concurrent.atomic.AtomicReference<String> credential =
            new java.util.concurrent.atomic.AtomicReference<>();

    public static void initialize(Properties properties) {
        String value = properties.getProperty("mcp.http.require.bearer", "false");
        if (!value.equals("true") && !value.equals("false")) {
            throw new IllegalArgumentException("Invalid mcp.http.require.bearer");
        }
        requireBearer = Boolean.parseBoolean(value);
    }

    public McpHttpSecurity(String url, HttpClient client, McpResponseLimits.State state) {
        this.endpoint = endpoint(url);
        this.bearer = requireBearer;
        this.state = state;
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new SecurityBlockedException("mcp-http-redirect-config");
        }
    }

    static URI endpoint(String value) {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (RuntimeException invalid) {
            throw new SecurityBlockedException("mcp-http-target");
        }
        boolean loopback = "127.0.0.1".equals(uri.getHost()) || "[::1]".equals(uri.getHost());
        if (uri.getHost() == null
                || uri.getRawUserInfo() != null
                || uri.getRawFragment() != null
                || !("https".equals(uri.getScheme())
                        || "http".equals(uri.getScheme()) && loopback)) {
            throw new SecurityBlockedException("mcp-http-target");
        }
        return uri;
    }

    public void check(HttpRequest request) {
        state.check();
        if (!endpoint.equals(request.uri())) {
            throw state.invalidate("mcp-http-target");
        }
        List<String> values = request.headers().allValues("Authorization");
        if (bearer && (values.size() != 1 || !validBearer(values.get(0)))) {
            throw state.invalidate("mcp-http-auth-required");
        }
        if (values.size() > 1
                || values.stream().anyMatch(value -> value.isEmpty() || value.length() > 8192)) {
            throw state.invalidate("mcp-http-auth-required");
        }
        String current;
        try {
            current =
                    java.util.HexFormat.of()
                            .formatHex(
                                    java.security.MessageDigest.getInstance("SHA-256")
                                            .digest(
                                                    (values.isEmpty()
                                                                    ? "absent:"
                                                                    : "present:" + values.get(0))
                                                            .getBytes(
                                                                    java.nio.charset
                                                                            .StandardCharsets
                                                                            .UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
        credential.compareAndSet(null, current);
        if (!credential.get().equals(current)) {
            throw state.invalidate("mcp-http-credential-changed");
        }
        // 携带任何 Authorization 的请求也必须走 HTTPS；只允许字面量 loopback 验收地址。
        if (!values.isEmpty()) {
            endpoint(request.uri().toString());
        }
    }

    private static boolean validBearer(String value) {
        if (value.length() < 8
                || value.length() > 8192
                || !value.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return false;
        }
        return value.substring(7).matches("[A-Za-z0-9._~+/-]+=*");
    }

    public SecurityBlockedException transportFailure(Throwable cause, SecurityContext context) {
        Throwable current = cause;
        for (int i = 0; i < 8; i++) {
            if (current instanceof SecurityBlockedException denied) {
                FailureDiagnostics.global()
                        .record(denied, Stage.MCP_EXECUTION, null, context, null, null);
                return denied;
            }
            if (current.getCause() == null || current.getCause() == current) {
                break;
            }
            current = current.getCause();
        }
        var failure = state.invalidate("mcp-http-transport-failed");
        FailureDiagnostics.global().record(failure, Stage.MCP_EXECUTION, null, context, null, null);
        return failure;
    }

    /** 响应头阶段拒绝，无需读取或记录服务端错误正文。 */
    public void response(int status, SecurityContext context) {
        String rule =
                status == 401 || status == 403
                        ? "mcp-http-auth-failed"
                        : status == 404
                                ? "mcp-http-session-expired"
                                : status >= 300 && status < 400
                                        ? "mcp-http-redirect"
                                        : status >= 500 ? "mcp-http-unavailable" : null;
        if (rule != null) {
            var failure = state.invalidate(rule);
            FailureDiagnostics.global()
                    .record(failure, Stage.MCP_EXECUTION, null, context, null, null);
            throw failure;
        }
    }
}
