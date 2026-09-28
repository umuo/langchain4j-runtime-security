package io.agentsecurity.demo;

import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.versioning.*;
import io.agentsecurity.policy.versioning.PolicyCompiler;
import java.util.Properties;

/** 普通 Java 独立进程中的 SPI 示例；测试依赖不会进入无 SDK 的生产 demo JAR。 */
public final class VersionedApplication implements VersionedDetector {
    private static final AtomicPolicy POLICIES =
            new AtomicPolicy(PolicyCompiler.compile("v1", new Properties(), null), 4);

    @Override
    public PolicyRevision snapshot() {
        return POLICIES.snapshot();
    }

    public static void main(String[] args) {
        var model = new Demo.MockModel(null, "ok");
        model.chat("hot-block");
        var changed = new Properties();
        changed.setProperty("deny.text", "hot-block");
        POLICIES.publish(1, PolicyCompiler.compile("v2", changed, null));
        try {
            model.chat("hot-block");
            throw new IllegalStateException("Updated policy did not block model");
        } catch (SecurityBlockedException expected) {
            if (!expected.ruleId().equals("denied-text")) {
                throw expected;
            }
        }
        POLICIES.rollback(2, "v1");
        model.chat("hot-block");
        if (Demo.modelCalls.get() != 2) {
            throw new IllegalStateException("Unexpected model side effects");
        }
        System.out.println("POLICY_CYCLE_OK calls=2 generation=" + POLICIES.state().generation());
    }
}
