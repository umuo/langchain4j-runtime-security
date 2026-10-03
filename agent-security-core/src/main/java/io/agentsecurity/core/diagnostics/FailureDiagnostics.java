package io.agentsecurity.core.diagnostics;

import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityEvent;
import io.agentsecurity.core.diagnostics.FailureRecord.Category;
import io.agentsecurity.core.diagnostics.FailureRecord.Stage;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicLongArray;

/** 固定维度计数与有界关联队列。诊断丢弃不改变安全判定，不调用宿主回调或网络。 */
public final class FailureDiagnostics {
    public record Count(Category category, Stage stage, long total) {}

    public record Snapshot(List<Count> counts, long dropped, int queued) {
        public Snapshot {
            counts = List.copyOf(counts);
        }
    }

    private static final FailureDiagnostics GLOBAL = new FailureDiagnostics(256);
    private final ArrayBlockingQueue<FailureRecord> queue;
    private final AtomicLongArray counts =
            new AtomicLongArray(Category.values().length * Stage.values().length);
    private final AtomicLong dropped = new AtomicLong();

    public FailureDiagnostics(int capacity) {
        if (capacity < 1 || capacity > 65536) {
            throw new IllegalArgumentException("Invalid failure diagnostics capacity");
        }
        queue = new ArrayBlockingQueue<>(capacity);
    }

    public static FailureDiagnostics global() {
        return GLOBAL;
    }

    /** 沿至多八层 cause 查找已诊断的安全拒绝，不复制任意异常消息或堆栈。 */
    public FailureRecord record(
            Throwable error,
            Stage stage,
            SecurityEvent.Phase phase,
            SecurityContext context,
            UUID eventId,
            String policyVersion) {
        java.util.Objects.requireNonNull(error);
        Throwable selected = error;
        SecurityBlockedException blocked = null;
        for (int i = 0; i < 8; i++) {
            if (selected instanceof SecurityBlockedException found) {
                blocked = found;
                break;
            }
            Throwable next = selected.getCause();
            if (next == null || next == selected) {
                break;
            }
            selected = next;
        }
        if (blocked != null && blocked.diagnostic() != null) {
            return blocked.diagnostic();
        }
        var invocation = context == null ? null : context.invocation();
        String rule = blocked == null ? null : blocked.ruleId();
        var record =
                new FailureRecord(
                        UUID.randomUUID(),
                        Instant.now(),
                        category(selected, rule),
                        stage,
                        boundary(phase),
                        stage == Stage.MCP_EXECUTION ? null : phase,
                        eventId,
                        context == null ? null : context.runId(),
                        invocation == null ? null : invocation.invocationId(),
                        invocation == null ? null : invocation.parentInvocationId(),
                        invocation == null ? 0 : invocation.depth(),
                        fingerprint(rule),
                        fingerprint(policyVersion));
        // 同一个安全拒绝在引擎、同步边界、Future 回调传播时只发布一次。
        if (blocked != null && !blocked.attachDiagnostic(record)) {
            return blocked.diagnostic();
        }
        publish(record);
        return record;
    }

    /** 转换器失败可能早于业务身份和检测事件创建，不伪造关联。 */
    public void instrumentationFailure() {
        publish(
                new FailureRecord(
                        UUID.randomUUID(),
                        Instant.now(),
                        Category.INSTRUMENTATION_FAILURE,
                        Stage.INSTRUMENTATION,
                        FailureRecord.Boundary.UNKNOWN,
                        null,
                        null,
                        null,
                        null,
                        null,
                        0,
                        null,
                        null));
    }

    private void publish(FailureRecord record) {
        counts.incrementAndGet(
                record.category().ordinal() * Stage.values().length + record.stage().ordinal());
        if (!queue.offer(record)) {
            dropped.incrementAndGet();
        }
    }

    private static FailureRecord.Boundary boundary(SecurityEvent.Phase phase) {
        if (phase == null) {
            return FailureRecord.Boundary.UNKNOWN;
        }
        String name = phase.name();
        // 优先匹配较长前缀，枚举来自 SDK，不解析业务名称。
        for (var boundary : FailureRecord.Boundary.values()) {
            if (name.startsWith(boundary.name() + "_")) {
                return boundary;
            }
        }
        return FailureRecord.Boundary.UNKNOWN;
    }

    private static Category category(Throwable error, String rule) {
        if (rule != null) {
            return switch (rule) {
                case "mcp-http-auth-required",
                                "mcp-http-auth-failed",
                                "mcp-http-credential-changed" ->
                        Category.AUTHENTICATION_FAILURE;
                case "mcp-http-session-expired" -> Category.SESSION_FAILURE;
                case "mcp-http-target", "mcp-http-redirect", "mcp-http-redirect-config" ->
                        Category.DESTINATION_FAILURE;
                case "mcp-http-unavailable", "mcp-http-transport-failed" ->
                        Category.TRANSPORT_FAILURE;
                case "instrumentation-error" -> Category.INSTRUMENTATION_FAILURE;
                case "audit-error", "agent-audit-error" -> Category.AUDIT_FAILURE;
                case "detector-timeout", "detector-remote-timeout", "mcp-pagination-timeout" ->
                        Category.TIMEOUT;
                case "agent-budget-invocations",
                                "agent-budget-checks",
                                "mcp-response-limit",
                                "mcp-pagination-pages",
                                "mcp-pagination-items",
                                "mcp-pagination-bytes",
                                "mcp-pagination-cursor",
                                "mcp-content-limit",
                                "mcp-schema-limit",
                                "text-limit",
                                "detector-capacity",
                                "detector-remote-capacity" ->
                        Category.CAPACITY_LIMIT;
                case "unsupported-mcp-version",
                                "unsupported-langchain4j-version",
                                "unsupported-mcp-content",
                                "mcp-discovery-metadata-unsupported",
                                "mcp-result-attributes-unsupported",
                                "adapter-shape-error",
                                "mcp-pagination-shape" ->
                        Category.UNSUPPORTED;
                case "detector-error",
                                "detector-closed",
                                "detector-load-error",
                                "detector-interrupted",
                                "detector-remote-request",
                                "detector-remote-interrupted",
                                "detector-remote-auth",
                                "detector-remote-http",
                                "detector-remote-protocol",
                                "detector-remote-transport" ->
                        Category.DETECTOR_FAILURE;
                default -> Category.POLICY_DENIED;
            };
        }
        if (error instanceof TimeoutException
                || error instanceof java.net.http.HttpTimeoutException) {
            return Category.TIMEOUT;
        }
        if (error instanceof CancellationException) {
            return Category.CANCELLED;
        }
        if (error instanceof java.io.IOException) {
            return Category.TRANSPORT_FAILURE;
        }
        // 不解析服务端错误消息来猜测认证失败或协议错误。
        return Category.EXECUTION_FAILURE;
    }

    /** 对不超过 256 个 UTF-16 单元的标识生成完整 SHA-256；超长标识不做散列。 */
    public static String fingerprint(String value) {
        if (value == null || value.length() > 256) {
            return null;
        }
        try {
            return HexFormat.of()
                    .formatHex(
                            MessageDigest.getInstance("SHA-256")
                                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    /** 破坏性读取；多个消费者会分走记录，导出失败重试由宿主管理。 */
    public List<FailureRecord> drain(int maximum) {
        if (maximum < 1 || maximum > 65536) {
            throw new IllegalArgumentException("Invalid batch size");
        }
        var result = new ArrayList<FailureRecord>();
        queue.drainTo(result, maximum);
        return List.copyOf(result);
    }

    public Snapshot snapshot() {
        var result = new ArrayList<Count>();
        for (var category : Category.values()) {
            for (var stage : Stage.values()) {
                result.add(
                        new Count(
                                category,
                                stage,
                                counts.get(
                                        category.ordinal() * Stage.values().length
                                                + stage.ordinal())));
            }
        }
        return new Snapshot(result, dropped.get(), queue.size());
    }
}
