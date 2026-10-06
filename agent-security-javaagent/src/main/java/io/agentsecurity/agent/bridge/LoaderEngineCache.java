package io.agentsecurity.agent.bridge;

import io.agentsecurity.core.PolicyEngine;
import io.agentsecurity.core.SecurityBlockedException;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.time.Duration;
import java.util.HashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

/** 按 ClassLoader 共享插件引擎；请求类持有条目，弱索引不阻止应用类加载器卸载。 */
final class LoaderEngineCache {

    private final HashMap<LoaderKey, WeakReference<Entry>> index = new HashMap<>();
    private final ReferenceQueue<ClassLoader> collected = new ReferenceQueue<>();
    private WeakReference<Entry> bootstrap;
    private final Function<ClassLoader, PolicyEngine> loader;
    private final long timeoutNanos;
    private final ClassValue<Entry> requests =
            new ClassValue<>() {
                @Override
                protected Entry computeValue(Class<?> requestClass) {
                    return entry(requestClass.getClassLoader());
                }
            };

    LoaderEngineCache(Function<ClassLoader, PolicyEngine> loader, Duration timeout) {
        this.loader = java.util.Objects.requireNonNull(loader);
        if (timeout == null || timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("Invalid plugin loading timeout");
        }
        timeoutNanos = timeout.toNanos();
    }

    PolicyEngine get(Class<?> requestClass) {
        return requests.get(requestClass).get();
    }

    private synchronized Entry entry(ClassLoader classLoader) {
        for (var key = collected.poll(); key != null; key = collected.poll()) {
            index.remove(key);
        }
        // 加载器按对象身份隔离，不能被自定义 equals/hashCode 合并。
        var key = classLoader == null ? null : new LoaderKey(classLoader, collected);
        WeakReference<Entry> reference = classLoader == null ? bootstrap : index.get(key);
        Entry entry = reference == null ? null : reference.get();
        if (entry == null) {
            entry =
                    new Entry(
                            new FutureTask<>(
                                    () ->
                                            java.util.Objects.requireNonNull(
                                                    loader.apply(classLoader))));
            if (classLoader == null) {
                bootstrap = new WeakReference<>(entry);
            } else {
                index.put(key, new WeakReference<>(entry));
            }
        }
        return entry;
    }

    private static final class LoaderKey extends WeakReference<ClassLoader> {
        private final int hash;

        LoaderKey(ClassLoader loader, ReferenceQueue<ClassLoader> collected) {
            super(loader, collected);
            hash = System.identityHashCode(loader);
        }

        @Override
        public int hashCode() {
            return hash;
        }

        @Override
        public boolean equals(Object other) {
            return this == other
                    || other instanceof LoaderKey key && get() != null && get() == key.get();
        }
    }

    private final class Entry {
        private final AtomicBoolean started = new AtomicBoolean();
        private final FutureTask<PolicyEngine> initialization;
        private volatile PolicyEngine ready;

        Entry(FutureTask<PolicyEngine> initialization) {
            this.initialization = initialization;
        }

        PolicyEngine get() {
            if (Thread.currentThread().isInterrupted()) {
                throw new SecurityBlockedException("detector-interrupted");
            }
            // 成功后的热路径只读取已就绪实例，不重复 CAS 或等待 Future。
            PolicyEngine cached = ready;
            if (cached != null) {
                return cached;
            }
            // 只初始化一次；不在全局索引锁内加载 SPI，不占用检测池等待其他请求。
            if (!started.get() && started.compareAndSet(false, true)) {
                initialization.run();
            }
            try {
                PolicyEngine initialized = initialization.get(timeoutNanos, TimeUnit.NANOSECONDS);
                ready = initialized;
                return initialized;
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                // 单个等待者取消不能取消其他调用共享的初始化。
                throw new SecurityBlockedException("detector-interrupted");
            } catch (TimeoutException timeout) {
                throw new SecurityBlockedException("detector-timeout");
            } catch (ExecutionException failed) {
                if (failed.getCause() instanceof SecurityBlockedException blocked) {
                    // 不复用同一个异常实例，避免并发调用混淆诊断和堆栈。
                    throw new SecurityBlockedException(blocked.ruleId());
                }
                throw new SecurityBlockedException("detector-load-error");
            }
        }
    }
}
