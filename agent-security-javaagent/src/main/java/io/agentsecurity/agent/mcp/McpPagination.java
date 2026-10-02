package io.agentsecurity.agent.mcp;

import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.health.McpDiagnostics;
import io.agentsecurity.core.health.McpDiagnostics.Limit;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.LongSupplier;

/** 对固定版本 fetchPaginatedList 的单次调用分配预算，预算独立，等待调用通过可嵌套且在出口清理的线程作用域关联。 */
public final class McpPagination {
    private record Settings(int pages, int items, int bytes, int timeoutMillis) {}

    private record Accessors(Method items, Method cursor) {}

    private static volatile Settings settings = new Settings(16, 128, 1_048_576, 30_000);
    private static final ThreadLocal<Budget> CURRENT = new ThreadLocal<>();
    private static final ClassValue<Accessors> ACCESSORS =
            new ClassValue<>() {
                @Override
                protected Accessors computeValue(Class<?> type) {
                    if (!type.getName().equals("dev.langchain4j.mcp.client.McpPage")) {
                        throw shape();
                    }
                    try {
                        Method items = type.getDeclaredMethod("items");
                        Method cursor = type.getDeclaredMethod("nextCursor");
                        if (!items.trySetAccessible() || !cursor.trySetAccessible()) {
                            throw shape();
                        }
                        return new Accessors(items, cursor);
                    } catch (ReflectiveOperationException | SecurityException error) {
                        throw shape();
                    }
                }
            };

    private McpPagination() {}

    public static void initialize(Properties properties) {
        settings =
                new Settings(
                        setting(properties, "mcp.pagination.max.pages", 16, 256),
                        setting(properties, "mcp.pagination.max.items", 128, 128),
                        setting(properties, "mcp.pagination.max.json.bytes", 1_048_576, 16_777_216),
                        setting(properties, "mcp.pagination.timeout.ms", 30_000, 300_000));
    }

    private static int setting(Properties properties, String name, int fallback, int max) {
        int value = Integer.parseInt(properties.getProperty(name, Integer.toString(fallback)));
        if (value < 1 || value > max) {
            throw new IllegalArgumentException("Invalid " + name);
        }
        return value;
    }

    public static Budget begin() {
        Settings current = settings;
        return new Budget(
                current.pages(),
                current.items(),
                current.bytes(),
                current.timeoutMillis(),
                McpDiagnostics.global(),
                System::nanoTime);
    }

    /** 仅替换固定客户端分页方法内的 Future.get，不修改其他业务的等待行为。 */
    public static <T> T await(CompletableFuture<T> future, long timeout, TimeUnit unit)
            throws InterruptedException, ExecutionException, TimeoutException {
        Budget budget = CURRENT.get();
        if (budget == null) {
            throw shape();
        }
        long remaining = budget.remaining();
        if (remaining <= 0) {
            budget.reject(Limit.PAGINATION_TIMEOUT);
            throw new TimeoutException("mcp-pagination-timeout");
        }
        try {
            return future.get(Math.min(unit.toNanos(timeout), remaining), TimeUnit.NANOSECONDS);
        } catch (TimeoutException failure) {
            if (budget.remaining() <= 0) {
                budget.reject(Limit.PAGINATION_TIMEOUT);
            }
            // 由原客户端取消 Future、清理 pendingOperations 并发送协议取消通知。
            throw failure;
        }
    }

    public static void enter(Budget budget) {
        budget.previous = CURRENT.get();
        CURRENT.set(budget);
    }

    /** 即使解析失败或超时也恢复外层预算，避免线程池复用时污染下一次查询。 */
    public static Throwable exit(Budget budget, Throwable failure) {
        try {
            if (failure == null && budget.remaining() <= 0) {
                budget.reject(Limit.PAGINATION_TIMEOUT);
            }
            if (budget.failure == Limit.PAGINATION_TIMEOUT) {
                failure = new SecurityBlockedException("mcp-pagination-timeout");
            }
            budget.finish(failure == null);
            return failure;
        } finally {
            if (budget.previous == null) {
                CURRENT.remove();
            } else {
                CURRENT.set(budget.previous);
            }
            budget.previous = null;
        }
    }

    public static <T> BiFunction<Long, String, T> requests(
            BiFunction<Long, String, T> delegate, Budget budget) {
        return (id, cursor) -> {
            budget.request();
            return delegate.apply(id, cursor);
        };
    }

    public static <T> Function<String, T> pages(Function<String, T> delegate, Budget budget) {
        return json -> {
            long bytes = budget.checkJson(json);
            T page = delegate.apply(json);
            if (page == null) {
                throw shape();
            }
            var accessors = ACCESSORS.get(page.getClass());
            try {
                Object values = accessors.items().invoke(page);
                Object cursor = accessors.cursor().invoke(page);
                if (!(values instanceof List<?> items)
                        || cursor != null && !(cursor instanceof String)) {
                    throw shape();
                }
                budget.accept(items.size(), bytes, (String) cursor);
                return page;
            } catch (ReflectiveOperationException error) {
                throw shape();
            }
        };
    }

    private static SecurityBlockedException shape() {
        return new SecurityBlockedException("mcp-pagination-shape");
    }

    /** 仅供同步分页调用拥有，每个查询独立实例；finish 必须由方法出口 finally 调用。 */
    public static final class Budget {
        private final int maxPages;
        private final int maxItems;
        private final int maxBytes;
        private final McpDiagnostics diagnostics;
        private final LongSupplier clock;
        private final long started;
        private final long timeoutNanos;
        private Budget previous;
        private final Set<String> cursors = new HashSet<>();
        private int pages;
        private int items;
        private int accepted;
        private long bytes;
        private Limit failure;
        private boolean finished;

        public Budget(int maxPages, int maxItems, int maxBytes, McpDiagnostics diagnostics) {
            this(maxPages, maxItems, maxBytes, 30_000, diagnostics, System::nanoTime);
        }

        // 测试注入单调时钟，避免边界测试依赖真实睡眠。
        Budget(
                int maxPages,
                int maxItems,
                int maxBytes,
                int timeoutMillis,
                McpDiagnostics diagnostics,
                LongSupplier clock) {
            if (timeoutMillis < 1 || timeoutMillis > 300_000) {
                throw new IllegalArgumentException("Invalid MCP pagination timeout");
            }
            if (maxPages < 1
                    || maxPages > 256
                    || maxItems < 1
                    || maxItems > 128
                    || maxBytes < 1
                    || maxBytes > 16_777_216) {
                throw new IllegalArgumentException("Invalid MCP pagination budget");
            }
            this.maxPages = maxPages;
            this.maxItems = maxItems;
            this.maxBytes = maxBytes;
            this.diagnostics = java.util.Objects.requireNonNull(diagnostics);
            this.clock = java.util.Objects.requireNonNull(clock);
            this.started = clock.getAsLong();
            this.timeoutNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
            diagnostics.paginationStarted();
        }

        public void request() {
            active();
            if (pages == maxPages) {
                throw reject(Limit.PAGINATION_PAGES);
            }
            pages++;
            diagnostics.pageRequested();
        }

        /** 计算解析器收到的 JSON 字符串的 UTF-8 长度，不再分配一份完整字节数组。 */
        public long checkJson(String json) {
            active();
            if (json == null) {
                throw shape();
            }
            long size = 0;
            for (int i = 0; i < json.length(); i++) {
                char c = json.charAt(i);
                if (c < 128) {
                    size++;
                } else if (c < 2048) {
                    size += 2;
                } else if (Character.isHighSurrogate(c)) {
                    if (++i >= json.length() || !Character.isLowSurrogate(json.charAt(i))) {
                        throw shape();
                    }
                    size += 4;
                } else if (Character.isLowSurrogate(c)) {
                    throw shape();
                } else {
                    size += 3;
                }
                if (size > maxBytes - bytes) {
                    throw reject(Limit.PAGINATION_BYTES);
                }
            }
            return size;
        }

        public void accept(int count, long size, String cursor) {
            active();
            if (accepted >= pages || count < 0 || size < 0 || size > maxBytes - bytes) {
                throw shape();
            }
            if (count > maxItems - items) {
                throw reject(Limit.PAGINATION_ITEMS);
            }
            if (cursor != null
                    && (cursor.isEmpty() || cursor.length() > 1024 || !cursors.add(cursor))) {
                throw reject(Limit.PAGINATION_CURSOR);
            }
            accepted++;
            items += count;
            bytes += size;
            diagnostics.pageAccepted(count, size);
        }

        private long remaining() {
            return timeoutNanos - (clock.getAsLong() - started);
        }

        private void active() {
            if (failure != null) {
                throw new SecurityBlockedException(rule(failure));
            }
            if (finished) {
                throw shape();
            }
            if (remaining() <= 0) {
                throw reject(Limit.PAGINATION_TIMEOUT);
            }
        }

        private SecurityBlockedException reject(Limit reason) {
            if (failure == null) {
                failure = reason;
                diagnostics.limit(reason);
            }
            return new SecurityBlockedException(rule(reason));
        }

        private static String rule(Limit reason) {
            return "mcp-pagination-"
                    + switch (reason) {
                        case PAGINATION_PAGES -> "pages";
                        case PAGINATION_ITEMS -> "items";
                        case PAGINATION_BYTES -> "bytes";
                        case PAGINATION_CURSOR -> "cursor";
                        case PAGINATION_TIMEOUT -> "timeout";
                        default -> throw new IllegalArgumentException("Not a pagination limit");
                    };
        }

        public void finish(boolean success) {
            if (!finished) {
                finished = true;
                diagnostics.paginationFinished(success && failure == null);
            }
        }
    }
}
