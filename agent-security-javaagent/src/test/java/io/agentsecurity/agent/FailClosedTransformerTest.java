package io.agentsecurity.agent;

import org.junit.jupiter.api.Test;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import static org.junit.jupiter.api.Assertions.*;

class FailClosedTransformerTest {
    private static class Loader extends ClassLoader {
        Class<?> define(byte[] bytes) { return defineClass(null, bytes, 0, bytes.length); }
    }

    @Test void byteBuddyReportedErrorRefusesClassDefinitionInsteadOfKillingProcess() throws Exception {
        ThreadLocal<Boolean> failed = new ThreadLocal<>();
        ClassFileTransformer delegate = new ClassFileTransformer() {
            @Override public byte[] transform(Module module, ClassLoader loader, String name, Class<?> type,
                    ProtectionDomain domain, byte[] bytes) {
                failed.set(true); return null; // Mirrors a transformer that reports and swallows its exception.
            }
        };
        byte[] original;
        try (var stream = getClass().getResourceAsStream("/io/agentsecurity/agent/StreamLimits.class")) {
            original = stream.readAllBytes();
        }
        var signals = new java.util.concurrent.atomic.AtomicInteger();
        byte[] rejected = new FailClosedTransformer(delegate, failed, signals::incrementAndGet)
                .transform(null, getClass().getClassLoader(), "fixture", null, null, original);
        assertThrows(ClassFormatError.class, () -> new Loader().define(rejected));
        assertNull(failed.get());
        assertEquals(1, signals.get());
    }
}
