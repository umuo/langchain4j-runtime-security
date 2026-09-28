package io.agentsecurity.core.versioning;

import io.agentsecurity.core.Decision;
import io.agentsecurity.core.Detector;
import io.agentsecurity.core.SecurityEvent;

/** 可作为 Detector SPI 实现。引擎在总预算内取得一次快照，再用该快照执行并标记审计版本。 */
public interface VersionedDetector extends Detector {
    PolicyRevision snapshot();

    @Override
    default Decision evaluate(SecurityEvent event) {
        var revision = snapshot();
        var decision = revision.detector().evaluate(event);
        return new Decision(decision.allowed(), decision.ruleId(), revision.version());
    }
}
