package io.agentsecurity.core;

import io.agentsecurity.core.delegation.DelegationGuard;
import io.agentsecurity.core.telemetry.SecurityTelemetry;
import java.util.List;
import java.util.function.BiConsumer;

/** 按顺序执行检测器，任一拒绝即终止检测；只有审计确认成功后才允许受保护操作继续。 */
public final class PolicyEngine implements AutoCloseable {

    private final List<Detector> detectors;
    private final io.agentsecurity.core.versioning.VersionedDetector versioned;

    private final BiConsumer<SecurityEvent, Decision> audit;

    private final DetectionLimits limits;

    private final DetectionExecutor executor;

    private final boolean owner;

    private final SecurityTelemetry telemetry;

    public PolicyEngine(List<Detector> detectors, BiConsumer<SecurityEvent, Decision> audit) {
        this(detectors, audit, DetectionLimits.defaults());
    }

    public PolicyEngine(
            List<Detector> detectors,
            BiConsumer<SecurityEvent, Decision> audit,
            DetectionLimits limits) {
        this(detectors, audit, limits, SecurityTelemetry.disabled());
    }

    /** 收集器由宿主管理，可与 AgentRuntime 共享，不执行导出网络请求。 */
    public PolicyEngine(
            List<Detector> detectors,
            BiConsumer<SecurityEvent, Decision> audit,
            DetectionLimits limits,
            SecurityTelemetry telemetry) {
        this(detectors, audit, limits, new DetectionExecutor(limits), true, telemetry);
    }

    private PolicyEngine(
            List<Detector> detectors,
            BiConsumer<SecurityEvent, Decision> audit,
            DetectionLimits limits,
            DetectionExecutor executor,
            boolean owner,
            SecurityTelemetry telemetry) {
        this.detectors = List.copyOf(detectors);
        var sources =
                this.detectors.stream()
                        .filter(
                                io.agentsecurity.core.versioning.VersionedDetector.class
                                        ::isInstance)
                        .toList();
        if (sources.size() > 1) {
            throw new IllegalArgumentException(
                    "Only one versioned policy source is supported per engine");
        }
        versioned =
                sources.isEmpty()
                        ? null
                        : (io.agentsecurity.core.versioning.VersionedDetector) sources.get(0);
        this.audit = java.util.Objects.requireNonNull(audit);
        this.limits = limits;
        this.executor = executor;
        this.owner = owner;
        this.telemetry = java.util.Objects.requireNonNull(telemetry);
    }

    /** 派生引擎共享执行池及其统计；仅覆盖隔离检测执行，包括 SPI 加载。 */
    public io.agentsecurity.core.health.WorkerHealth detectorHealth() {
        return executor.health();
    }

    public PolicyEngine withAdditionalDetectors(List<Detector> additional) {
        var combined = new java.util.ArrayList<>(detectors);
        combined.addAll(additional);
        return new PolicyEngine(combined, audit, limits, executor, false, telemetry);
    }

    /** 显式固定一个策略版本用于完整任务，异步任务应传递此视图；共享池由原引擎关闭。 */
    public PolicyEngine pinPolicy() {
        if (versioned == null) {
            throw new IllegalStateException("No versioned policy source");
        }
        var revision =
                java.util.Objects.requireNonNull(
                        executor.run(
                                versioned::snapshot,
                                System.nanoTime() + limits.timeout().toNanos()));
        io.agentsecurity.core.versioning.VersionedDetector fixed = () -> revision;
        var selected =
                detectors.stream()
                        .map(detector -> detector == versioned ? (Detector) fixed : detector)
                        .toList();
        return new PolicyEngine(selected, audit, limits, executor, false, telemetry);
    }

    /** SPI 的延迟加载也受执行时限约束，避免扩展初始化阻塞受保护调用。 */
    public List<Detector> loadDetectors(java.util.concurrent.Callable<List<Detector>> loader) {
        return List.copyOf(executor.run(loader, System.nanoTime() + limits.timeout().toNanos()));
    }

    /** 所有检测器共享同一个截止时间；检测或审计失败均抛出可识别的阻断异常。 */
    public void check(SecurityEvent event) {
        long started = System.nanoTime();
        var outcome = SecurityTelemetry.Outcome.INTERNAL_ERROR;
        try {
            checkInternal(event);
            outcome = SecurityTelemetry.Outcome.ALLOW;
        } catch (SecurityBlockedException error) {
            outcome =
                    error.ruleId().equals("audit-error")
                            ? SecurityTelemetry.Outcome.AUDIT_FAILURE
                            : error.ruleId().startsWith("detector-")
                                    ? SecurityTelemetry.Outcome.DETECTOR_FAILURE
                                    : SecurityTelemetry.Outcome.DENY;
            throw error;
        } finally {
            telemetry.record(event, outcome, System.nanoTime() - started);
        }
    }

    private void checkInternal(SecurityEvent event) {
        Decision decision = DelegationGuard.evaluate(event);
        long deadline = System.nanoTime() + limits.timeout().toNanos();
        if (executor.isClosed()) {
            decision = Decision.deny("detector-closed");
        }
        String policyVersion = versioned == null ? null : "unresolved";
        io.agentsecurity.core.versioning.PolicyRevision revision = null;
        if (versioned != null && decision.allowed()) {
            try {
                revision =
                        java.util.Objects.requireNonNull(
                                executor.run(versioned::snapshot, deadline));
                policyVersion = revision.version();
            } catch (SecurityBlockedException denied) {
                decision = Decision.deny(denied.ruleId());
            } catch (RuntimeException invalid) {
                decision = Decision.deny("detector-error");
            }
        }
        for (Detector configured : detectors) {
            Detector detector =
                    configured == versioned && revision != null ? revision.detector() : configured;
            if (!decision.allowed()) {
                break;
            }
            try {
                // 只有执行成本可控且不可继承的内置策略在当前线程运行，扩展检测器统一隔离执行。
                decision =
                        java.util.Objects.requireNonNull(
                                detector instanceof LocalPolicy
                                                || detector instanceof RequiredContextPolicy
                                        ? detector.evaluate(event)
                                        : executor.run(
                                                () -> {
                                                    try (var scope =
                                                            SecurityContexts.restore(
                                                                    event.context())) {
                                                        return detector.evaluate(event);
                                                    }
                                                },
                                                deadline));
            } catch (SecurityBlockedException e) {
                decision = Decision.deny(e.ruleId());
            } catch (RuntimeException e) {
                decision = Decision.deny("detector-error");
            }
            if (!decision.allowed()) {
                break;
            }
        }
        // 检测器可能耗时，放行前再次确认父任务及委托没有失效。
        if (decision.allowed()) {
            decision = DelegationGuard.evaluate(event);
        }
        decision = new Decision(decision.allowed(), decision.ruleId(), policyVersion);
        // 审计成功是放行的前置条件，写入失败时不得继续执行受保护操作。
        try {
            audit.accept(event, decision);
        } catch (RuntimeException e) {
            throw diagnosed("audit-error", event, policyVersion);
        }
        if (!decision.allowed()) {
            throw diagnosed(decision.ruleId(), event, policyVersion);
        }
    }

    private static SecurityBlockedException diagnosed(
            String rule, SecurityEvent event, String version) {
        var failure = new SecurityBlockedException(rule);
        io.agentsecurity.core.diagnostics.FailureDiagnostics.global()
                .record(
                        failure,
                        io.agentsecurity.core.diagnostics.FailureRecord.Stage.POLICY_EVALUATION,
                        event.phase(),
                        event.context(),
                        event.id(),
                        version);
        return failure;
    }

    @Override
    public void close() {
        if (owner) {
            executor.close();
        }
    }
}
