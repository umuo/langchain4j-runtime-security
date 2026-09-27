package io.agentsecurity.core.telemetry;

import io.agentsecurity.core.SecurityEvent;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicLongArray;

/** 有界、无外部回调的进程内收集器。业务线程只更新计数和尝试入队，导出由宿主异步拉取。 */
public final class SecurityTelemetry {
    /** 有限结果维度，避免插件规则名及用户数据导致指标基数增长。 */
    public enum Outcome {
        ALLOW,
        DENY,
        DETECTOR_FAILURE,
        AUDIT_FAILURE,
        INTERNAL_ERROR
    }

    /** 每个桶为独立区间计数；上界依次为 1ms、10ms、100ms、1s、无穷。 */
    public record Metric(
            SecurityEvent.Phase phase,
            Outcome outcome,
            long count,
            List<Long> durationBuckets,
            long durationNanosTotal) {}

    /** 并发快照是近似值；多项计数不保证来自同一个原子时间点。 */
    public record Snapshot(List<Metric> metrics, long dropped, int queued) {}

    private static final SecurityTelemetry DISABLED = new SecurityTelemetry();
    private static final SecurityTelemetry GLOBAL = new SecurityTelemetry(256, 1);
    private final ArrayBlockingQueue<TelemetryRecord> queue;
    private final AtomicLongArray counts;
    private final AtomicLongArray buckets;
    private final AtomicLongArray durations;
    private final AtomicLong sequence = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final int sampleEvery;

    private SecurityTelemetry() {
        queue = null;
        counts = null;
        buckets = null;
        durations = null;
        sampleEvery = 1;
    }

    /** sampleEvery 按 run 散列采样；无上下文按事件序号采样。指标不采样。 */
    public SecurityTelemetry(int capacity, int sampleEvery) {
        if (capacity < 1 || capacity > 65536 || sampleEvery < 1 || sampleEvery > 1000000) {
            throw new IllegalArgumentException("Invalid telemetry limits");
        }
        queue = new ArrayBlockingQueue<>(capacity);
        int dimensions = SecurityEvent.Phase.values().length * Outcome.values().length;
        counts = new AtomicLongArray(dimensions);
        buckets = new AtomicLongArray(dimensions * 5);
        durations = new AtomicLongArray(dimensions);
        this.sampleEvery = sampleEvery;
    }

    public static SecurityTelemetry disabled() {
        return DISABLED;
    }

    /** Java Agent 与同一核心类加载器下的业务共享此实例；默认不会自动接入检测引擎。 */
    public static SecurityTelemetry global() {
        return GLOBAL;
    }

    /** 不调用任何用户导出逻辑，也不等待队列空间；满队列丢弃新关联记录。 */
    public void record(SecurityEvent event, Outcome outcome, long durationNanos) {
        if (queue == null) {
            return;
        }
        Objects.requireNonNull(event);
        Objects.requireNonNull(outcome);
        long duration = Math.max(0, durationNanos);
        int index = event.phase().ordinal() * Outcome.values().length + outcome.ordinal();
        counts.incrementAndGet(index);
        durations.addAndGet(index, duration);
        int bucket =
                duration <= 1000000
                        ? 0
                        : duration <= 10000000
                                ? 1
                                : duration <= 100000000 ? 2 : duration <= 1000000000 ? 3 : 4;
        buckets.incrementAndGet(index * 5 + bucket);
        var context = event.context();
        long samplingKey =
                context == null
                        ? sequence.getAndIncrement()
                        : context.runId().getMostSignificantBits()
                                ^ context.runId().getLeastSignificantBits();
        if (Long.remainderUnsigned(samplingKey, sampleEvery) != 0) {
            return;
        }
        var invocation = context == null ? null : context.invocation();
        boolean terminal =
                event.phase() == SecurityEvent.Phase.AGENT_FINISH
                        || event.phase() == SecurityEvent.Phase.AGENT_REVOKE
                        || event.phase() == SecurityEvent.Phase.AGENT_EXPIRE;
        var record =
                new TelemetryRecord(
                        Instant.now(),
                        event.id(),
                        event.phase(),
                        outcome,
                        duration,
                        context == null ? null : context.runId(),
                        invocation == null ? null : invocation.invocationId(),
                        invocation == null ? null : invocation.parentInvocationId(),
                        invocation == null ? 0 : invocation.depth(),
                        invocation == null || !terminal ? null : invocation.endReason(),
                        invocation == null || !terminal ? 0 : invocation.lifetimeNanos());
        if (!queue.offer(record)) {
            dropped.incrementAndGet();
        }
    }

    /** 破坏性读取，多个消费者竞争分配记录；失败重试和持久化由导出适配器负责。 */
    public List<TelemetryRecord> drain(int maximum) {
        if (maximum < 1 || maximum > 65536) {
            throw new IllegalArgumentException("Invalid telemetry batch size");
        }
        var result = new ArrayList<TelemetryRecord>();
        if (queue != null) {
            queue.drainTo(result, maximum);
        }
        return List.copyOf(result);
    }

    public Snapshot snapshot() {
        var metrics = new ArrayList<Metric>();
        if (counts != null) {
            for (var phase : SecurityEvent.Phase.values()) {
                for (var outcome : Outcome.values()) {
                    int index = phase.ordinal() * Outcome.values().length + outcome.ordinal();
                    var histogram = new ArrayList<Long>();
                    for (int bucket = 0; bucket < 5; bucket++) {
                        histogram.add(buckets.get(index * 5 + bucket));
                    }
                    metrics.add(
                            new Metric(
                                    phase,
                                    outcome,
                                    counts.get(index),
                                    List.copyOf(histogram),
                                    durations.get(index)));
                }
            }
        }
        return new Snapshot(List.copyOf(metrics), dropped.get(), queue == null ? 0 : queue.size());
    }
}
