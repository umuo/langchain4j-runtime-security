package io.agentsecurity.agent.bridge;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.Detector;
import io.agentsecurity.core.PolicyEngine;
import io.agentsecurity.core.SecurityBlockedException;
import java.lang.ref.WeakReference;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** 覆盖加载器共享、并发初始化、失败持续拒绝和类加载器回收，避免弱键强值循环引用。 */
class LoaderEngineCacheTest {

    private static class FirstRequest {}

    private static class SecondRequest {}

    private static class RequestLoader extends ClassLoader {
        RequestLoader() {
            super(LoaderEngineCacheTest.class.getClassLoader());
        }

        Class<?> copy(Class<?> source) throws Exception {
            byte[] bytes;
            try (var input = source.getResourceAsStream(source.getSimpleName() + ".class")) {
                // 内部类的资源名包含外部类前缀。
                if (input != null) {
                    bytes = input.readAllBytes();
                } else {
                    try (var nested =
                            source.getResourceAsStream(
                                    "/" + source.getName().replace('.', '/') + ".class")) {
                        bytes = nested.readAllBytes();
                    }
                }
            }
            return defineClass(source.getName(), bytes, 0, bytes.length);
        }
    }

    @Test
    void requestClassesShareOneEngineButDifferentLoadersRemainIsolated() throws Exception {
        AtomicInteger loads = new AtomicInteger();
        try (var engine = new PolicyEngine(List.of(), (event, decision) -> {})) {
            var cache =
                    new LoaderEngineCache(
                            loader -> {
                                loads.incrementAndGet();
                                return engine.withAdditionalDetectors(List.of());
                            },
                            Duration.ofSeconds(1));
            var firstLoader = new RequestLoader();
            Class<?> first = firstLoader.copy(FirstRequest.class);
            Class<?> second = firstLoader.copy(SecondRequest.class);
            assertSame(cache.get(first), cache.get(second));
            assertNotSame(
                    cache.get(first), cache.get(new RequestLoader().copy(FirstRequest.class)));
            assertEquals(2, loads.get());
        }
    }

    @Test
    void customLoaderEqualityCannotMergeDifferentApplications() throws Exception {
        class EqualLoader extends RequestLoader {
            @Override
            public boolean equals(Object other) {
                return other instanceof EqualLoader;
            }

            @Override
            public int hashCode() {
                return 1;
            }
        }
        try (var engine = new PolicyEngine(List.of(), (event, decision) -> {})) {
            var cache =
                    new LoaderEngineCache(
                            loader -> engine.withAdditionalDetectors(List.of()),
                            Duration.ofSeconds(1));
            assertNotSame(
                    cache.get(new EqualLoader().copy(FirstRequest.class)),
                    cache.get(new EqualLoader().copy(FirstRequest.class)));
        }
    }

    @Test
    void concurrentClassesInitializeOnlyOnce() throws Exception {
        AtomicInteger loads = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try (var engine = new PolicyEngine(List.of(), (event, decision) -> {})) {
            var cache =
                    new LoaderEngineCache(
                            loader -> {
                                loads.incrementAndGet();
                                entered.countDown();
                                try {
                                    if (!release.await(2, TimeUnit.SECONDS)) {
                                        throw new AssertionError("初始化等待超时");
                                    }
                                } catch (InterruptedException interrupted) {
                                    throw new AssertionError(interrupted);
                                }
                                return engine;
                            },
                            Duration.ofSeconds(2));
            var pool = Executors.newFixedThreadPool(4);
            try {
                var first = pool.submit(() -> cache.get(FirstRequest.class));
                assertTrue(entered.await(1, TimeUnit.SECONDS));
                var second = pool.submit(() -> cache.get(SecondRequest.class));
                release.countDown();
                assertSame(first.get(2, TimeUnit.SECONDS), second.get(2, TimeUnit.SECONDS));
                assertEquals(1, loads.get());
            } finally {
                release.countDown();
                pool.shutdownNow();
            }
        }
    }

    @Test
    void waitingTimeoutDoesNotCancelSharedInitializationAndOtherLoadersProceed() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try (var engine = new PolicyEngine(List.of(), (event, decision) -> {})) {
            var cache =
                    new LoaderEngineCache(
                            loader -> {
                                if (loader == FirstRequest.class.getClassLoader()) {
                                    entered.countDown();
                                    try {
                                        release.await();
                                    } catch (InterruptedException interrupted) {
                                        throw new AssertionError(interrupted);
                                    }
                                }
                                return engine;
                            },
                            Duration.ofMillis(50));
            var pool = Executors.newSingleThreadExecutor();
            try {
                var first = pool.submit(() -> cache.get(FirstRequest.class));
                assertTrue(entered.await(1, TimeUnit.SECONDS));
                assertEquals(
                        "detector-timeout",
                        assertThrows(
                                        SecurityBlockedException.class,
                                        () -> cache.get(SecondRequest.class))
                                .ruleId());
                assertSame(engine, cache.get(new RequestLoader().copy(FirstRequest.class)));
                release.countDown();
                assertSame(engine, first.get(1, TimeUnit.SECONDS));
                assertSame(engine, cache.get(SecondRequest.class));
            } finally {
                release.countDown();
                pool.shutdownNow();
            }
        }
    }

    @Test
    void initializationFailureIsCachedAndPreservesSafeRuleId() {
        AtomicInteger loads = new AtomicInteger();
        var cache =
                new LoaderEngineCache(
                        loader -> {
                            loads.incrementAndGet();
                            throw new SecurityBlockedException("detector-timeout");
                        },
                        Duration.ofSeconds(1));
        var first =
                assertThrows(SecurityBlockedException.class, () -> cache.get(FirstRequest.class));
        var second =
                assertThrows(SecurityBlockedException.class, () -> cache.get(SecondRequest.class));
        assertEquals("detector-timeout", first.ruleId());
        assertEquals("detector-timeout", second.ruleId());
        assertNotSame(first, second);
        assertEquals(1, loads.get());
    }

    @Test
    void indexDoesNotRetainLoaderEvenWhenPluginInstanceReferencesIt() throws Exception {
        try (var engine = new PolicyEngine(List.of(), (event, decision) -> {})) {
            var cache =
                    new LoaderEngineCache(
                            loader -> {
                                Detector plugin =
                                        (Detector)
                                                Proxy.newProxyInstance(
                                                        loader,
                                                        new Class<?>[] {Detector.class},
                                                        (proxy, method, args) -> null);
                                return engine.withAdditionalDetectors(List.of(plugin));
                            },
                            Duration.ofSeconds(1));
            WeakReference<ClassLoader> reference = createDisposableLoader(cache);
            for (int attempt = 0; attempt < 100 && reference.get() != null; attempt++) {
                System.gc();
                Thread.sleep(20);
            }
            assertNull(reference.get(), "缓存不应阻止 ClassLoader 回收");
        }
    }

    private WeakReference<ClassLoader> createDisposableLoader(LoaderEngineCache cache)
            throws Exception {
        var loader = new RequestLoader();
        cache.get(loader.copy(FirstRequest.class));
        return new WeakReference<>(loader);
    }
}
