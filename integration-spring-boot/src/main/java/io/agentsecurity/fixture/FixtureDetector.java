package io.agentsecurity.fixture;

import io.agentsecurity.core.Decision;
import io.agentsecurity.core.Detector;
import io.agentsecurity.core.ResourceRef;
import io.agentsecurity.core.SecurityEvent;

/** 应用侧检测器 SPI 测试实现，模拟授权、拒绝、超时与异常；不访问外部服务。 */
public final class FixtureDetector implements Detector {
    static volatile Detector remote;

    @Override
    public Decision evaluate(SecurityEvent event) {
        var configured = remote;
        if (configured != null) {
            return configured.evaluate(event);
        }
        // Fixture ACL represents a trusted resource-owner lookup, independent of the requested
        // memory ID.
        if (event.resource() != null
                && event.resource()
                        .equals(new ResourceRef("memory:string", "private-memory-session"))
                && (event.context() == null
                        || !event.context().tenantId().equals("memory-tenant-a"))) {
            return Decision.deny("memory-owner-denied");
        }
        if (event.phase() == SecurityEvent.Phase.RETRIEVAL_INPUT
                && event.context() != null
                && !event.context().permissions().contains("knowledge:read")) {
            return Decision.deny("rag-permission-denied");
        }
        if (event.text().contains("PLUGIN_SLEEP")) {
            try {
                Thread.sleep(10_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (event.text().contains("PLUGIN_FAILURE")) {
            throw new IllegalStateException("sensitive detector detail");
        }
        return event.text().contains("PLUGIN_DENY")
                ? Decision.deny("boot-plugin")
                : Decision.allow();
    }
}
