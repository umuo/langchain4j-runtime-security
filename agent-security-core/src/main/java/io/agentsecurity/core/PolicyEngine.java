package io.agentsecurity.core;

import io.agentsecurity.core.delegation.DelegationGuard;
import java.util.List;
import java.util.function.BiConsumer;

/** 按顺序执行检测器，任一拒绝即终止检测；只有审计确认成功后才允许受保护操作继续。 */
public final class PolicyEngine implements AutoCloseable {

    private final List<Detector> detectors;

    private final BiConsumer<SecurityEvent, Decision> audit;

    private final DetectionLimits limits;

    private final DetectionExecutor executor;

    private final boolean owner;

    public PolicyEngine(List<Detector> detectors, BiConsumer<SecurityEvent, Decision> audit) {
        this(detectors, audit, DetectionLimits.defaults());
    }

    public PolicyEngine(
            List<Detector> detectors,
            BiConsumer<SecurityEvent, Decision> audit,
            DetectionLimits limits) {
        this(detectors, audit, limits, new DetectionExecutor(limits), true);
    }

    private PolicyEngine(
            List<Detector> detectors,
            BiConsumer<SecurityEvent, Decision> audit,
            DetectionLimits limits,
            DetectionExecutor executor,
            boolean owner) {
        this.detectors = List.copyOf(detectors);
        this.audit = java.util.Objects.requireNonNull(audit);
        this.limits = limits;
        this.executor = executor;
        this.owner = owner;
    }

    public PolicyEngine withAdditionalDetectors(List<Detector> additional) {
        var combined = new java.util.ArrayList<>(detectors);
        combined.addAll(additional);
        return new PolicyEngine(combined, audit, limits, executor, false);
    }

    /** SPI 的延迟加载也受执行时限约束，避免扩展初始化阻塞受保护调用。 */
    public List<Detector> loadDetectors(java.util.concurrent.Callable<List<Detector>> loader) {
        return List.copyOf(executor.run(loader, System.nanoTime() + limits.timeout().toNanos()));
    }

    /** 所有检测器共享同一个截止时间；检测或审计失败均抛出可识别的阻断异常。 */
    public void check(SecurityEvent event) {
        Decision decision = DelegationGuard.evaluate(event);
        long deadline = System.nanoTime() + limits.timeout().toNanos();
        if (executor.isClosed()) {
            decision = Decision.deny("detector-closed");
        }
        for (Detector detector : detectors) {
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
        // 审计成功是放行的前置条件，写入失败时不得继续执行受保护操作。
        try {
            audit.accept(event, decision);
        } catch (RuntimeException e) {
            throw new SecurityBlockedException("audit-error");
        }
        if (!decision.allowed()) {
            throw new SecurityBlockedException(decision.ruleId());
        }
    }

    @Override
    public void close() {
        if (owner) {
            executor.close();
        }
    }
}
