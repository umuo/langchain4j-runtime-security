package io.agentsecurity.core.versioning;

import io.agentsecurity.core.Detector;
import java.util.Objects;

/** 已编译的不可变策略描述。自定义 detector 的不可变性和摘要真实性由可信构建方保证。 */
public record PolicyRevision(String version, String sha256, Detector detector) {
    public PolicyRevision {
        if (version == null
                || !version.matches("[a-zA-Z0-9_.-]{1,80}")
                || version.equals("unresolved")
                || sha256 == null
                || !sha256.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Invalid policy revision");
        }
        Objects.requireNonNull(detector);
        if (detector instanceof VersionedDetector) {
            throw new IllegalArgumentException("Nested versioned policies are not supported");
        }
    }
}
