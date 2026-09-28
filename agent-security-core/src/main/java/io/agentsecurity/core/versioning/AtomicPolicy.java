package io.agentsecurity.core.versioning;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;

/** 有界的进程内策略发布器。编译在外部完成；检测读取不等待管理锁，没有自动文件监听。 */
public final class AtomicPolicy implements VersionedDetector {
    public record State(long generation, String version, String sha256) {}

    private record Current(long generation, PolicyRevision revision) {}

    private final LinkedHashMap<String, PolicyRevision> revisions = new LinkedHashMap<>();
    private final int maximumVersions;
    private volatile Current current;

    public AtomicPolicy(PolicyRevision initial, int maximumVersions) {
        Objects.requireNonNull(initial);
        if (maximumVersions < 1 || maximumVersions > 256) {
            throw new IllegalArgumentException("Invalid policy history capacity");
        }
        this.maximumVersions = maximumVersions;
        revisions.put(initial.version(), initial);
        current = new Current(1, initial);
    }

    @Override
    public PolicyRevision snapshot() {
        return current.revision();
    }

    public State state() {
        var value = current;
        return describe(value);
    }

    /** expectedGeneration 为乐观并发控制，不是认证；调用者必须由可信管理入口授权。 */
    public synchronized State publish(long expectedGeneration, PolicyRevision candidate) {
        Objects.requireNonNull(candidate);
        requireGeneration(expectedGeneration);
        var existing = revisions.get(candidate.version());
        if (existing != null && !existing.sha256().equals(candidate.sha256())) {
            throw new IllegalArgumentException(
                    "Policy version already identifies different content");
        }
        if (existing == null && revisions.size() >= maximumVersions) {
            throw new IllegalStateException("Policy history capacity reached");
        }
        var selected = existing == null ? candidate : existing;
        long next = Math.incrementExact(current.generation());
        revisions.putIfAbsent(selected.version(), selected);
        current = new Current(next, selected);
        return state();
    }

    /** 回滚同样推进序号，旧发布请求不能在回滚后借相同版本名覆盖当前状态。 */
    public synchronized State rollback(long expectedGeneration, String version) {
        requireGeneration(expectedGeneration);
        var revision = revisions.get(version);
        if (revision == null) {
            throw new IllegalArgumentException("Unknown policy version");
        }
        current = new Current(Math.incrementExact(current.generation()), revision);
        return state();
    }

    /** 只读版本目录，不暴露规则或检测器对象；容量满时拒绝新增版本，不悄悄丢弃回滚目标。 */
    public synchronized List<String> versions() {
        return List.copyOf(revisions.keySet());
    }

    private void requireGeneration(long expected) {
        if (current.generation() != expected) {
            throw new IllegalStateException("Stale policy generation");
        }
    }

    private static State describe(Current value) {
        return new State(value.generation(), value.revision().version(), value.revision().sha256());
    }
}
