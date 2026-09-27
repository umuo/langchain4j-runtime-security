package io.agentsecurity.core;

import java.util.List;
import java.util.function.BiConsumer;

public final class PolicyEngine implements AutoCloseable {
    private final List<Detector> detectors;
    private final BiConsumer<SecurityEvent, Decision> audit;
    private final DetectionLimits limits;
    private final DetectionExecutor executor;
    private final boolean owner;

    public PolicyEngine(List<Detector> detectors, BiConsumer<SecurityEvent, Decision> audit) {
        this(detectors, audit, DetectionLimits.defaults());
    }

    public PolicyEngine(List<Detector> detectors, BiConsumer<SecurityEvent, Decision> audit, DetectionLimits limits) {
        this(detectors, audit, limits, new DetectionExecutor(limits), true);
    }

    private PolicyEngine(List<Detector> detectors, BiConsumer<SecurityEvent, Decision> audit,
                         DetectionLimits limits, DetectionExecutor executor, boolean owner) {
        this.detectors = List.copyOf(detectors);
        this.audit = java.util.Objects.requireNonNull(audit);
        this.limits = limits; this.executor = executor; this.owner = owner;
    }

    public PolicyEngine withAdditionalDetectors(List<Detector> additional) {
        var combined = new java.util.ArrayList<>(detectors);
        combined.addAll(additional);
        return new PolicyEngine(combined, audit, limits, executor, false);
    }

    /** Bounds lazy SPI construction as well as detector evaluation. */
    public List<Detector> loadDetectors(java.util.concurrent.Callable<List<Detector>> loader) {
        return List.copyOf(executor.run(loader, System.nanoTime() + limits.timeout().toNanos()));
    }

    public void check(SecurityEvent event) {
        Decision decision = Decision.allow();
        long deadline = System.nanoTime() + limits.timeout().toNanos();
        if (executor.isClosed()) decision = Decision.deny("detector-closed");
        for (Detector detector : detectors) {
            if (!decision.allowed()) break;
            try {
                // Only the bounded, final built-in literal policy executes inline. All extension code is isolated.
                decision = java.util.Objects.requireNonNull(detector instanceof LocalPolicy || detector instanceof RequiredContextPolicy
                        ? detector.evaluate(event) : executor.run(() -> {
                            try (var scope = SecurityContexts.restore(event.context())) { return detector.evaluate(event); }
                        }, deadline));
            } catch (SecurityBlockedException e) {
                decision = Decision.deny(e.ruleId());
            } catch (RuntimeException e) {
                decision = Decision.deny("detector-error");
            }
            if (!decision.allowed()) break;
        }
        // Audit failure must never result in a protected operation being executed.
        try { audit.accept(event, decision); }
        catch (RuntimeException e) { throw new SecurityBlockedException("audit-error"); }
        if (!decision.allowed()) throw new SecurityBlockedException(decision.ruleId());
    }

    @Override public void close() { if (owner) executor.close(); }
}
