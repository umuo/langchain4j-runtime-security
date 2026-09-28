package io.agentsecurity.policy.remote;

import io.agentsecurity.core.Decision;
import io.agentsecurity.core.Detector;
import io.agentsecurity.core.SecurityEvent;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.*;
import java.util.function.Function;

/** 有界远程检测器。任何接入故障均拒绝；HttpClient/TLS 和内容最小化由可信宿主管理。 */
public final class RemoteHttpDetector implements Detector {
    private final HttpClient client;
    private final RemoteDetectorSettings settings;
    private final Map<String, String> headers;
    private final Function<SecurityEvent, String> content;
    private final Semaphore permits;

    /** 不自动注册、不打印原文或认证信息，不主动重试，不关闭宿主持有的 HTTP 客户端。 */
    public RemoteHttpDetector(
            HttpClient client,
            RemoteDetectorSettings settings,
            Map<String, String> authenticationHeaders,
            Function<SecurityEvent, String> minimizedContent) {
        this.client = Objects.requireNonNull(client);
        this.settings = Objects.requireNonNull(settings);
        this.content = Objects.requireNonNull(minimizedContent);
        if (client.followRedirects() != HttpClient.Redirect.NEVER
                || client.authenticator().isPresent()
                || client.cookieHandler().isPresent()) {
            throw new IllegalArgumentException(
                    "Disable redirects, challenge authentication and cookies");
        }
        headers = Map.copyOf(authenticationHeaders);
        var names = new HashSet<String>();
        for (var header : headers.entrySet()) {
            String name = header.getKey().toLowerCase(Locale.ROOT);
            if (!Set.of("authorization", "x-api-key").contains(name)
                    || !names.add(name)
                    || header.getValue().isBlank()
                    || header.getValue().length() > 4096
                    || header.getValue().chars().anyMatch(c -> c < 32 || c > 126)) {
                throw new IllegalArgumentException("Invalid remote authentication headers");
            }
        }
        permits = new Semaphore(settings.maxConcurrent());
    }

    @Override
    public Decision evaluate(SecurityEvent event) {
        Objects.requireNonNull(event);
        if (!settings.phases().contains(event.phase())) {
            return Decision.allow();
        }
        if (Thread.currentThread().isInterrupted()) {
            return failure("interrupted");
        }
        if (!permits.tryAcquire()) {
            return failure("capacity");
        }
        CompletableFuture<HttpResponse<byte[]>> response = null;
        long deadline = System.nanoTime() + settings.timeout().toNanos();
        try {
            byte[] body;
            try {
                body =
                        RemoteProtocol.request(
                                event,
                                settings.policyVersion(),
                                content.apply(event),
                                settings.maxRequestBytes());
            } catch (Exception invalidContent) {
                return failure("request");
            }
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                return failure("timeout");
            }
            if (Thread.currentThread().isInterrupted()) {
                return failure("interrupted");
            }
            var request =
                    HttpRequest.newBuilder(settings.endpoint())
                            .timeout(Duration.ofNanos(remaining))
                            .header("Content-Type", "application/json")
                            .header("Accept", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofByteArray(body));
            headers.forEach(request::header);
            response = client.sendAsync(request.build(), ignored -> new BoundedResponse());
            remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                return failure("timeout");
            }
            var result = response.get(remaining, TimeUnit.NANOSECONDS);
            if (result.statusCode() == 401 || result.statusCode() == 403) {
                return failure("auth");
            }
            if (result.statusCode() != 200) {
                return failure("http");
            }
            String type =
                    result.headers().firstValue("Content-Type").orElse("").split(";", 2)[0].trim();
            if (!type.equalsIgnoreCase("application/json")
                    || result.headers().firstValue("Content-Encoding").isPresent()) {
                return failure("protocol");
            }
            try {
                boolean allowed =
                        RemoteProtocol.allowed(result.body(), event, settings.policyVersion());
                if (System.nanoTime() - deadline >= 0) {
                    return failure("timeout");
                }
                return allowed ? Decision.allow() : Decision.deny("remote-denied");
            } catch (Exception invalidResponse) {
                return failure("protocol");
            }
        } catch (TimeoutException timeout) {
            return failure("timeout");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return failure("interrupted");
        } catch (ExecutionException transport) {
            return failure(
                    transport.getCause() instanceof java.net.http.HttpTimeoutException
                            ? "timeout"
                            : "transport");
        } catch (RuntimeException invalid) {
            return failure("transport");
        } finally {
            if (response != null && !response.isDone()) {
                response.cancel(true);
            }
            permits.release();
        }
    }

    private static Decision failure(String reason) {
        return Decision.deny("detector-remote-" + reason);
    }
}
