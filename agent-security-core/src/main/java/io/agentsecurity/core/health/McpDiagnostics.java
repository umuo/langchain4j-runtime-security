package io.agentsecurity.core.health;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLongArray;
import java.util.concurrent.atomic.LongAdder;

/** MCP 容量与分页诊断，只保存固定维度计数，不保留服务、身份、URI、游标或正文。 */
public final class McpDiagnostics {
    public enum Limit {
        HTTP_RESPONSE_BYTES,
        STDIO_LINE_BYTES,
        PAGINATION_PAGES,
        PAGINATION_ITEMS,
        PAGINATION_BYTES,
        PAGINATION_CURSOR
    }

    public record Snapshot(
            Map<Limit, Long> limits,
            long transportFailures,
            long failedStateChecks,
            long paginationStarted,
            long paginationCompleted,
            long paginationFailed,
            long pagesRequested,
            long pagesAccepted,
            long itemsAccepted,
            long jsonBytesAccepted) {
        public Snapshot {
            limits = Map.copyOf(limits);
        }
    }

    private static final McpDiagnostics GLOBAL = new McpDiagnostics();
    private final AtomicLongArray limits = new AtomicLongArray(Limit.values().length);
    private final LongAdder transportFailures = new LongAdder();
    private final LongAdder failedStateChecks = new LongAdder();
    private final LongAdder started = new LongAdder();
    private final LongAdder completed = new LongAdder();
    private final LongAdder failed = new LongAdder();
    private final LongAdder requested = new LongAdder();
    private final LongAdder accepted = new LongAdder();
    private final LongAdder items = new LongAdder();
    private final LongAdder bytes = new LongAdder();

    public static McpDiagnostics global() {
        return GLOBAL;
    }

    /** 每次独立分页拒绝或每个传输首次超限调用一次。 */
    public void limit(Limit reason) {
        limits.incrementAndGet(reason.ordinal());
    }

    public void transportFailed() {
        transportFailures.increment();
    }

    public void failedStateChecked() {
        failedStateChecks.increment();
    }

    public void paginationStarted() {
        started.increment();
    }

    public void paginationFinished(boolean success) {
        if (success) {
            completed.increment();
        } else {
            failed.increment();
        }
    }

    public void pageRequested() {
        requested.increment();
    }

    public void pageAccepted(int count, long jsonBytes) {
        accepted.increment();
        items.add(count);
        bytes.add(jsonBytes);
    }

    /** 并发采样不是跨计数器的原子快照，不能据瞬时差值判断泄漏。 */
    public Snapshot snapshot() {
        var counts = new EnumMap<Limit, Long>(Limit.class);
        for (Limit reason : Limit.values()) {
            counts.put(reason, limits.get(reason.ordinal()));
        }
        return new Snapshot(
                counts,
                transportFailures.sum(),
                failedStateChecks.sum(),
                started.sum(),
                completed.sum(),
                failed.sum(),
                requested.sum(),
                accepted.sum(),
                items.sum(),
                bytes.sum());
    }
}
