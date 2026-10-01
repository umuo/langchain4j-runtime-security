package io.agentsecurity.agent.instrumentation;

import io.agentsecurity.agent.bridge.Bridge;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/** 增强失败时拒绝定义目标类，防止 JVM 忽略转换异常后执行未经保护的原始字节码。 */
final class FailClosedTransformer implements ClassFileTransformer {

    private final ClassFileTransformer delegate;

    private final ThreadLocal<Boolean> failed;

    private final Runnable failureSignal;

    FailClosedTransformer(ClassFileTransformer delegate, ThreadLocal<Boolean> failed) {
        this(delegate, failed, Bridge::transformationFailed);
    }

    FailClosedTransformer(
            ClassFileTransformer delegate, ThreadLocal<Boolean> failed, Runnable failureSignal) {
        this.delegate = delegate;
        this.failed = failed;
        this.failureSignal = failureSignal;
    }

    @Override
    public byte[] transform(
            Module module,
            ClassLoader loader,
            String name,
            Class<?> redefining,
            ProtectionDomain domain,
            byte[] bytes) {
        // 与 AgentBuilder.ignore 保持一致，在读取类型描述前排除 JDK/SDK 自身，
        // 避免不需要增强的基础类参与 Byte Buddy 的加载与解析。
        if (name != null
                && (name.startsWith("java/")
                        || name.startsWith("jdk/")
                        || name.startsWith("sun/")
                        || name.startsWith("net/bytebuddy/")
                        || name.startsWith("io/agentsecurity/agent/")
                        || name.startsWith("io/agentsecurity/core/")
                        || name.startsWith("io/agentsecurity/policy/")
                        || name.startsWith("io/agentsecurity/shaded/"))) {
            return null;
        }
        Boolean parent = failed.get();
        failed.remove();
        try {
            byte[] transformed =
                    delegate.transform(module, loader, name, redefining, domain, bytes);
            if (Boolean.TRUE.equals(failed.get())) {
                failureSignal.run();
                // JVM ignores transformer exceptions. Invalid bytes force a ClassFormatError
                // instead.
                return new byte[0];
            }
            return transformed;
        } catch (java.lang.instrument.IllegalClassFormatException
                | RuntimeException
                | LinkageError error) {
            failureSignal.run();
            System.err.println(
                    "[agent-security] TRANSFORM_ERROR class-definition-rejected type="
                            + name
                            + " error="
                            + error.getClass().getName());
            return new byte[0];
        } finally {
            if (parent == null) {
                failed.remove();
            } else {
                failed.set(parent);
            }
        }
    }
}
