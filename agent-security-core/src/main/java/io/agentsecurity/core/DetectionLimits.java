package io.agentsecurity.core;

import java.time.Duration;

/** One deadline for the complete detector chain, with no unbounded waiting queue. */
public record DetectionLimits(Duration timeout, int maxConcurrency) {
    public DetectionLimits {
        if (timeout == null || timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofMinutes(1)) > 0)
            throw new IllegalArgumentException("Detector timeout must be in (0, 60 seconds]");
        if (maxConcurrency < 1 || maxConcurrency > 256) throw new IllegalArgumentException("Invalid detector concurrency");
    }
    public static DetectionLimits defaults() { return new DetectionLimits(Duration.ofMillis(500), 4); }
}
