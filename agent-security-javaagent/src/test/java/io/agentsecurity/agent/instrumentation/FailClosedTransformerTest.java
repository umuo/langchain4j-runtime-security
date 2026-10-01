package io.agentsecurity.agent.instrumentation;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.agent.stream.StreamLimits;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.junit.jupiter.api.Test;

class FailClosedTransformerTest {

    private static class Loader extends ClassLoader {

        Class<?> define(byte[] bytes) {
            return defineClass(null, bytes, 0, bytes.length);
        }
    }

    @Test
    void byteBuddyReportedErrorRefusesClassDefinitionInsteadOfKillingProcess() throws Exception {
        ThreadLocal<Boolean> failed = new ThreadLocal<>();
        ClassFileTransformer delegate =
                new ClassFileTransformer() {

                    @Override
                    public byte[] transform(
                            Module module,
                            ClassLoader loader,
                            String name,
                            Class<?> type,
                            ProtectionDomain domain,
                            byte[] bytes) {
                        // Mirrors a transformer that reports and swallows its exception.
                        failed.set(true);
                        return null;
                    }
                };
        byte[] original;
        try (var stream = StreamLimits.class.getResourceAsStream("StreamLimits.class")) {
            original = stream.readAllBytes();
        }
        var signals = new java.util.concurrent.atomic.AtomicInteger();
        byte[] rejected =
                new FailClosedTransformer(delegate, failed, signals::incrementAndGet)
                        .transform(
                                null, getClass().getClassLoader(), "fixture", null, null, original);
        assertThrows(ClassFormatError.class, () -> new Loader().define(rejected));
        assertNull(failed.get());
        assertEquals(1, signals.get());
    }

    @Test
    void excludedRuntimeClassesNeverEnterByteBuddyButApplicationFailuresStillReject()
            throws Exception {
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        var signals = new java.util.concurrent.atomic.AtomicInteger();
        ClassFileTransformer delegate =
                new ClassFileTransformer() {
                    @Override
                    public byte[] transform(
                            Module module,
                            ClassLoader loader,
                            String name,
                            Class<?> type,
                            ProtectionDomain domain,
                            byte[] bytes) {
                        calls.incrementAndGet();
                        throw new ClassCircularityError();
                    }
                };
        var transformer =
                new FailClosedTransformer(delegate, new ThreadLocal<>(), signals::incrementAndGet);
        for (String name :
                java.util.List.of(
                        "java/util/HashMap",
                        "jdk/internal/Foo",
                        "sun/security/Foo",
                        "net/bytebuddy/Foo",
                        "io/agentsecurity/agent/Foo",
                        "io/agentsecurity/core/Foo",
                        "io/agentsecurity/policy/Foo",
                        "io/agentsecurity/shaded/Foo")) {
            assertNull(transformer.transform(null, null, name, null, null, new byte[0]));
        }
        assertEquals(0, calls.get());
        assertEquals(0, signals.get());
        assertArrayEquals(
                new byte[0],
                transformer.transform(null, null, "fixture/Foo", null, null, new byte[0]));
        assertEquals(1, signals.get());
    }
}
