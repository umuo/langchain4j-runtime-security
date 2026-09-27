package io.agentsecurity.telemetry;

import io.agentsecurity.core.telemetry.SecurityTelemetry;
import io.agentsecurity.core.telemetry.TelemetryRecord;
import java.net.URI;
import java.net.http.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** 单工作线程、单在途批次的 OTLP/HTTP JSON 日志导出器。失败不会进入安全决策链。 */
public final class OtlpLogExporter implements AutoCloseable {
    /** 进程内累计值；pending 表示已取出但尚未确认或丢弃的记录数。 */
    public record Health(
            long attempts,
            long failures,
            long timeouts,
            long accepted,
            long dropped,
            int pending) {}

    private final SecurityTelemetry telemetry;
    private final HttpClient client;
    private final URI endpoint;
    private final String service;
    private final Map<String, String> headers;
    private final Duration timeout;
    private final long intervalMillis;
    private final int batchSize;
    private final int maxAttempts;
    private final Thread worker;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicLong attempts = new AtomicLong();
    private final AtomicLong failures = new AtomicLong();
    private final AtomicLong timeouts = new AtomicLong();
    private final AtomicLong accepted = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicInteger pending = new AtomicInteger();

    /** endpoint 是完整日志端点；HttpClient 由宿主管理，必须禁用重定向。构造后开始消费。 */
    public OtlpLogExporter(
            SecurityTelemetry telemetry,
            HttpClient client,
            URI endpoint,
            String service,
            Map<String, String> headers,
            Duration interval,
            Duration timeout,
            int batchSize,
            int maxAttempts) {
        this.telemetry = Objects.requireNonNull(telemetry);
        this.client = Objects.requireNonNull(client);
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("Redirects must be disabled");
        }
        if (endpoint == null
                || endpoint.getHost() == null
                || endpoint.getUserInfo() != null
                || endpoint.getFragment() != null
                || endpoint.getQuery() != null
                || !(endpoint.getScheme().equals("https") || endpoint.getScheme().equals("http"))) {
            throw new IllegalArgumentException("Invalid telemetry endpoint");
        }
        if (service == null
                || !service.matches("[a-zA-Z0-9_.-]{1,128}")
                || batchSize < 1
                || batchSize > 256
                || maxAttempts < 1
                || maxAttempts > 3
                || interval == null
                || interval.compareTo(Duration.ofMillis(10)) < 0
                || interval.compareTo(Duration.ofMinutes(1)) > 0
                || timeout == null
                || timeout.compareTo(Duration.ofMillis(10)) < 0
                || timeout.compareTo(Duration.ofSeconds(30)) > 0) {
            throw new IllegalArgumentException("Invalid exporter limits");
        }
        this.endpoint = endpoint;
        this.service = service;
        this.headers = Map.copyOf(headers);
        if (headers.size() > 16) {
            throw new IllegalArgumentException("Too many headers");
        }
        for (var entry : headers.entrySet()) {
            if (!entry.getKey().matches("[a-zA-Z0-9-]{1,80}")
                    || entry.getValue().length() > 4096
                    || entry.getValue().chars().anyMatch(c -> c < 32 || c > 126)
                    || java.util.Set.of(
                                    "content-type",
                                    "content-length",
                                    "host",
                                    "connection",
                                    "expect",
                                    "upgrade",
                                    "accept-encoding")
                            .contains(entry.getKey().toLowerCase(java.util.Locale.ROOT))) {
                throw new IllegalArgumentException("Invalid exporter header");
            }
        }
        this.timeout = timeout;
        this.intervalMillis = interval.toMillis();
        this.batchSize = batchSize;
        this.maxAttempts = maxAttempts;
        worker = new Thread(this::run, "agent-security-otlp");
        worker.setDaemon(true);
        worker.setContextClassLoader(OtlpLogExporter.class.getClassLoader());
        worker.start();
    }

    private void run() {
        try {
            while (!closed.get()) {
                var batch = telemetry.drain(batchSize);
                if (!batch.isEmpty()) {
                    pending.set(batch.size());
                    try {
                        export(batch);
                    } finally {
                        dropped.addAndGet(pending.getAndSet(0));
                    }
                }
                Thread.sleep(intervalMillis);
            }
        } catch (InterruptedException stopped) {
            Thread.currentThread().interrupt();
        } finally {
            closed.set(true);
        }
    }

    private void export(List<TelemetryRecord> batch) throws InterruptedException {
        byte[] body;
        try {
            body = OtlpJson.encode(service, batch);
        } catch (Exception invalid) {
            failures.incrementAndGet();
            return;
        }
        if (body.length > 1048576) {
            failures.incrementAndGet();
            return;
        }
        for (int attempt = 0; attempt < maxAttempts && !closed.get(); attempt++) {
            long delay =
                    Math.min(30000, 100L * (1L << attempt))
                            + ThreadLocalRandom.current().nextLong(100);
            CompletableFuture<HttpResponse<byte[]>> request = null;
            boolean retry = false;
            attempts.incrementAndGet();
            try {
                var builder =
                        HttpRequest.newBuilder(endpoint)
                                .timeout(timeout)
                                .header("Content-Type", "application/json")
                                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
                headers.forEach(builder::header);
                request = client.sendAsync(builder.build(), info -> new BoundedResponse());
                var response = request.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
                if (response.statusCode() == 200) {
                    if (!response.headers()
                                    .firstValue("Content-Type")
                                    .orElse("")
                                    .split(";", 2)[0]
                                    .trim()
                                    .equalsIgnoreCase("application/json")
                            || response.headers()
                                    .firstValue("Content-Encoding")
                                    .filter(v -> !v.equalsIgnoreCase("identity"))
                                    .isPresent()) {
                        failures.incrementAndGet();
                        return;
                    }
                    int rejected = OtlpJson.rejected(response.body(), batch.size());
                    accepted.addAndGet(batch.size() - rejected);
                    dropped.addAndGet(rejected);
                    pending.set(0);
                    if (rejected > 0) {
                        failures.incrementAndGet();
                    }
                    return;
                }
                failures.incrementAndGet();
                retry = java.util.Set.of(429, 502, 503, 504).contains(response.statusCode());
                delay = retryDelay(response, delay);
            } catch (TimeoutException timeoutError) {
                failures.incrementAndGet();
                timeouts.incrementAndGet();
                retry = true;
            } catch (ExecutionException failed) {
                failures.incrementAndGet();
                Throwable cause = failed.getCause();
                if (cause instanceof HttpTimeoutException) {
                    timeouts.incrementAndGet();
                }
                retry =
                        cause instanceof java.io.IOException
                                && !(cause instanceof BoundedResponse.TooLarge);
            } catch (java.io.IOException | RuntimeException invalid) {
                // 非法 JSON、超界响应和不可恢复配置错误不重试，避免重复发送已被部分接收的批次。
                failures.incrementAndGet();
            } finally {
                if (request != null && !request.isDone()) {
                    request.cancel(true);
                }
            }
            if (!retry || attempt + 1 >= maxAttempts || delay > 30000) {
                return;
            }
            Thread.sleep(delay);
        }
    }

    private static long retryDelay(HttpResponse<?> response, long fallback) {
        var header = response.headers().firstValue("Retry-After");
        if (header.isEmpty()) {
            return fallback;
        }
        try {
            long seconds = Long.parseLong(header.get());
            return seconds < 0 ? fallback : seconds > 30 ? 30001 : seconds * 1000;
        } catch (NumberFormatException dateValue) {
            try {
                long delay =
                        Duration.between(
                                        Instant.now(),
                                        ZonedDateTime.parse(
                                                        header.get(),
                                                        DateTimeFormatter.RFC_1123_DATE_TIME)
                                                .toInstant())
                                .toMillis();
                return Math.max(0, delay);
            } catch (RuntimeException invalid) {
                return fallback;
            }
        }
    }

    public Health health() {
        return new Health(
                attempts.get(),
                failures.get(),
                timeouts.get(),
                accepted.get(),
                dropped.get(),
                pending.get());
    }

    /** 停止并中断在途请求，不等待远端，不隐式刷新；尚在收集器中的记录由宿主负责。 */
    @Override
    public void close() {
        closed.set(true);
        worker.interrupt();
    }
}
