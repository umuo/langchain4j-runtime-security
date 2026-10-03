package io.agentsecurity.agent.bridge;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.health.AgentCoverage;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.implementation.FixedValue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class LangChain4jCompatibilityTest {
    @ParameterizedTest
    @ValueSource(strings = {"1.20.0", "1.20.1", "1.20.42", "1.21.0", "1.21.1"})
    void admitsStablePatchesAfterCheckingTheRealApi(String version) {
        assertTrue(LangChain4jCompatibility.accepts(version));
        var loader = new MetadataLoader(version);
        long passed = AgentCoverage.global().snapshot().versionChecksPassed();
        assertDoesNotThrow(() -> Bridge.verifyBoundary(boundary(loader)));
        assertDoesNotThrow(() -> Bridge.verifyBoundary(boundary(loader)));
        assertEquals(1, loader.reads);
        assertEquals(passed + 1, AgentCoverage.global().snapshot().versionChecksPassed());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(
            strings = {
                "1.19.9",
                "1.22.0",
                "2.0.0",
                "1.20",
                "1.20.01",
                "1.20.-1",
                "1.20.1-SNAPSHOT",
                "1.20.0-beta30",
                "1.20.0+build",
                " 1.20.0"
            })
    void rejectsUnknownSeriesPrereleasesAndMalformedVersions(String version) {
        assertFalse(LangChain4jCompatibility.accepts(version));
        String reason =
                version == null ? "missing-version-metadata" : "unsupported-langchain4j-version";
        assertReason(reason, () -> Bridge.verifyBoundary(boundary(new MetadataLoader(version))));
    }

    @Test
    void rejectsMissingApisAndDoesNotCacheAFailedCheck() {
        var loader =
                new MetadataLoader("1.20.1") {
                    @Override
                    protected Class<?> loadClass(String name, boolean resolve)
                            throws ClassNotFoundException {
                        if (name.equals("dev.langchain4j.model.chat.ChatModel")) {
                            throw new ClassNotFoundException("private dependency details");
                        }
                        return super.loadClass(name, resolve);
                    }
                };
        long failed = AgentCoverage.global().snapshot().versionChecksFailed();
        for (int i = 0; i < 2; i++) {
            assertReason(
                    "incompatible-langchain4j-api", () -> Bridge.verifyBoundary(boundary(loader)));
        }
        assertEquals(2, loader.reads);
        assertEquals(failed + 2, AgentCoverage.global().snapshot().versionChecksFailed());
    }

    @Test
    void rejectsChangedReturnTypesEvenWithTheBaselineVersion() {
        byte[] changed =
                new ByteBuddy()
                        .subclass(Object.class)
                        .name("dev.langchain4j.model.chat.request.ChatRequest")
                        .defineMethod("messages", String.class, Visibility.PUBLIC)
                        .intercept(FixedValue.value("private business data"))
                        .make()
                        .getBytes();
        var loader =
                new MetadataLoader("1.20.0") {
                    @Override
                    protected Class<?> loadClass(String name, boolean resolve)
                            throws ClassNotFoundException {
                        if (name.equals("dev.langchain4j.model.chat.request.ChatRequest")) {
                            synchronized (getClassLoadingLock(name)) {
                                Class<?> type = findLoadedClass(name);
                                return type != null
                                        ? type
                                        : defineClass(name, changed, 0, changed.length);
                            }
                        }
                        return super.loadClass(name, resolve);
                    }
                };
        assertReason("incompatible-langchain4j-api", () -> Bridge.verifyBoundary(boundary(loader)));
    }

    private static void assertReason(
            String reason, org.junit.jupiter.api.function.Executable action) {
        var failure = assertThrows(SecurityBlockedException.class, action);
        assertEquals("Agent security blocked operation: " + reason, failure.getMessage());
        assertNull(failure.getCause());
    }

    private static Object boundary(MetadataLoader loader) {
        try {
            return loader.boundary().getConstructor().newInstance();
        } catch (ReflectiveOperationException failure) {
            throw new AssertionError(failure);
        }
    }

    private static class MetadataLoader extends ClassLoader {
        private final String version;
        int reads;
        private Class<?> boundary;

        MetadataLoader(String version) {
            super(LangChain4jCompatibilityTest.class.getClassLoader());
            this.version = version;
        }

        Class<?> boundary() {
            if (boundary == null) {
                byte[] bytes =
                        new ByteBuddy()
                                .subclass(Object.class)
                                .name("fixture.Boundary")
                                .make()
                                .getBytes();
                boundary = defineClass("fixture.Boundary", bytes, 0, bytes.length);
            }
            return boundary;
        }

        @Override
        public InputStream getResourceAsStream(String name) {
            if (name.equals("META-INF/maven/dev.langchain4j/langchain4j-core/pom.properties")) {
                reads++;
                return version == null
                        ? null
                        : new ByteArrayInputStream(
                                ("version=" + version.replace(" ", "\\ ") + "\n")
                                        .getBytes(StandardCharsets.UTF_8));
            }
            return super.getResourceAsStream(name);
        }
    }
}
