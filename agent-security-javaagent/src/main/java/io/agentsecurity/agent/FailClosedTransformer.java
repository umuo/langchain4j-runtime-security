package io.agentsecurity.agent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/** Rejects the failed class definition; never kills the hosting JVM. */
final class FailClosedTransformer implements ClassFileTransformer {
    private final ClassFileTransformer delegate;
    private final ThreadLocal<Boolean> failed;
    private final Runnable failureSignal;

    FailClosedTransformer(ClassFileTransformer delegate, ThreadLocal<Boolean> failed) {
        this(delegate, failed, Bridge::transformationFailed);
    }

    FailClosedTransformer(ClassFileTransformer delegate, ThreadLocal<Boolean> failed, Runnable failureSignal) {
        this.delegate = delegate;
        this.failed = failed;
        this.failureSignal = failureSignal;
    }

    @Override public byte[] transform(Module module, ClassLoader loader, String name, Class<?> redefining,
                                      ProtectionDomain domain, byte[] bytes) {
        Boolean parent = failed.get();
        failed.remove();
        try {
            byte[] transformed = delegate.transform(module, loader, name, redefining, domain, bytes);
            if (Boolean.TRUE.equals(failed.get())) {
                failureSignal.run();
                // JVM ignores transformer exceptions. Invalid bytes force a ClassFormatError instead.
                return new byte[0];
            }
            return transformed;
        } catch (java.lang.instrument.IllegalClassFormatException | RuntimeException | LinkageError error) {
            failureSignal.run();
            System.err.println("[agent-security] TRANSFORM_ERROR class-definition-rejected");
            return new byte[0];
        } finally {
            if (parent == null) failed.remove(); else failed.set(parent);
        }
    }
}
