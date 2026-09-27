package io.agentsecurity.core;

import java.time.Duration;

/** 检测链总时间预算及并发上限，不等同于整个业务请求的超时时间。 */
public record DetectionLimits(Duration timeout, int maxConcurrency) {

    public DetectionLimits {
        if (timeout == null
                || timeout.isNegative()
                || timeout.isZero()
                || timeout.compareTo(Duration.ofMinutes(1)) > 0) {
            throw new IllegalArgumentException("Detector timeout must be in (0, 60 seconds]");
        }
        if (maxConcurrency < 1 || maxConcurrency > 256) {
            throw new IllegalArgumentException("Invalid detector concurrency");
        }
    }

    public static DetectionLimits defaults() {
        return new DetectionLimits(Duration.ofMillis(500), 4);
    }
}
