package io.agentsecurity.core.health;

import java.util.LinkedHashSet;
import java.util.List;

/** 有界插桩诊断。不持有 Class 或 ClassLoader，不代表未加载代码已经受到保护。 */
public final class AgentCoverage {
    public static final String SUPPORTED_LANGCHAIN4J = "1.20.0";

    public record Snapshot(
            boolean installed,
            boolean failed,
            long transformations,
            long failures,
            long omittedNames,
            long versionChecksPassed,
            long versionChecksFailed,
            List<String> transformedTypes,
            WorkerHealth detector,
            WorkerHealth audit) {}

    private static final AgentCoverage GLOBAL = new AgentCoverage();
    private final LinkedHashSet<String> names = new LinkedHashSet<>();
    private boolean installed;
    private boolean failed;
    private long transformations;
    private long failures;
    private long omitted;
    private long versionsPassed;
    private long versionsFailed;
    private io.agentsecurity.core.PolicyEngine engine;
    private io.agentsecurity.core.BoundedAuditSink audit;

    /** Java Agent 启动时绑定宿主拥有的内置实例；仅用于诊断，不改变授权状态。 */
    public synchronized void bind(
            io.agentsecurity.core.PolicyEngine engine,
            io.agentsecurity.core.BoundedAuditSink audit) {
        this.engine = java.util.Objects.requireNonNull(engine);
        this.audit = java.util.Objects.requireNonNull(audit);
    }

    public static AgentCoverage global() {
        return GLOBAL;
    }

    /** 仅在 transformer 注册成功后标记；启动成功不等于全部边界覆盖。 */
    public synchronized void installed() {
        installed = true;
    }

    /** 记录变换通知次数；重复类名可能来自不同加载器，不等同于唯一类数量。 */
    public synchronized void transformed(String name) {
        transformations++;
        if (name == null || name.length() > 256 || !name.matches("[a-zA-Z0-9_.$]+")) {
            omitted++;
        } else if (!names.contains(name)) {
            if (names.size() < 128) {
                names.add(name);
            } else {
                omitted++;
            }
        }
    }

    /** 故障粘滞；诊断没有重置接口，也不能恢复已失效的安全引擎。 */
    public synchronized void transformationFailed() {
        failed = true;
        failures++;
    }

    /** 校验执行次数，缓存命中不递增；不统计唯一加载器，避免保留加载器引用。 */
    public synchronized void versionChecked(boolean supported) {
        if (supported) {
            versionsPassed++;
        } else {
            versionsFailed++;
        }
    }

    /** 不持有诊断锁访问线程池，避免与类加载及线程创建形成锁顺序环。 */
    public Snapshot snapshot() {
        io.agentsecurity.core.PolicyEngine currentEngine;
        io.agentsecurity.core.BoundedAuditSink currentAudit;
        Snapshot state;
        synchronized (this) {
            currentEngine = engine;
            currentAudit = audit;
            state =
                    new Snapshot(
                            installed,
                            failed,
                            transformations,
                            failures,
                            omitted,
                            versionsPassed,
                            versionsFailed,
                            List.copyOf(names),
                            null,
                            null);
        }
        return new Snapshot(
                state.installed(),
                state.failed(),
                state.transformations(),
                state.failures(),
                state.omittedNames(),
                state.versionChecksPassed(),
                state.versionChecksFailed(),
                state.transformedTypes(),
                currentEngine == null ? null : currentEngine.detectorHealth(),
                currentAudit == null ? null : currentAudit.health());
    }
}
