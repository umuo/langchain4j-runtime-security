package io.agentsecurity.agent.mcp;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.health.McpDiagnostics;
import io.agentsecurity.core.health.McpDiagnostics.Limit;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class McpPaginationTest {
    @Test
    void deadlineRejectsExactBoundaryAndDoesNotCountTwice() {
        var clock = new AtomicLong(Long.MAX_VALUE - 100);
        var metrics = new McpDiagnostics();
        var budget = new McpPagination.Budget(4, 4, 1024, 1, metrics, clock::get);
        budget.request();
        clock.addAndGet(1_000_000); // nanoTime 回绕后，差值仍正确。
        assertEquals(
                "mcp-pagination-timeout",
                assertThrows(SecurityBlockedException.class, () -> budget.accept(1, 2, null))
                        .ruleId());
        assertThrows(SecurityBlockedException.class, budget::request);
        budget.finish(false);
        assertEquals(1, metrics.snapshot().limits().get(Limit.PAGINATION_TIMEOUT));
        assertEquals(0, metrics.snapshot().pagesAccepted());
    }

    @Test
    void waitUsesRemainingBudgetAndKeepsNativeTimeoutForCancellation() throws Exception {
        var clock = new AtomicLong();
        var metrics = new McpDiagnostics();
        var budget = new McpPagination.Budget(4, 4, 1024, 100, metrics, clock::get);
        var future =
                new CompletableFuture<String>() {
                    @Override
                    public String get(long timeout, TimeUnit unit) throws TimeoutException {
                        assertEquals(60_000_000, unit.toNanos(timeout));
                        clock.addAndGet(60_000_000);
                        throw new TimeoutException();
                    }
                };
        McpPagination.enter(budget);
        Throwable failure = new AssertionError("Wait did not complete");
        try {
            clock.set(40_000_000);
            failure =
                    assertThrows(
                            TimeoutException.class,
                            () -> McpPagination.await(future, 2, TimeUnit.SECONDS));
        } finally {
            assertInstanceOf(SecurityBlockedException.class, McpPagination.exit(budget, failure));
        }
        assertEquals(1, metrics.snapshot().paginationFailed());
        assertEquals(1, metrics.snapshot().limits().get(Limit.PAGINATION_TIMEOUT));
        assertThrows(
                SecurityBlockedException.class,
                () -> McpPagination.await(future, 1, TimeUnit.SECONDS));
    }

    @Test
    void shorterPageTimeoutIsNotRelabeledAsTotalDeadline() {
        var clock = new AtomicLong();
        var metrics = new McpDiagnostics();
        var budget = new McpPagination.Budget(4, 4, 1024, 100, metrics, clock::get);
        var expected = new TimeoutException();
        var future =
                new CompletableFuture<String>() {
                    @Override
                    public String get(long timeout, TimeUnit unit) throws TimeoutException {
                        assertEquals(10_000_000, unit.toNanos(timeout));
                        clock.addAndGet(10_000_000);
                        throw expected;
                    }
                };
        McpPagination.enter(budget);
        Throwable failure =
                assertThrows(
                        TimeoutException.class,
                        () -> McpPagination.await(future, 10, TimeUnit.MILLISECONDS));
        assertSame(expected, McpPagination.exit(budget, failure));
        assertEquals(0, metrics.snapshot().limits().get(Limit.PAGINATION_TIMEOUT));
    }

    @Test
    void nestedScopeRestoresOuterBudgetAndExpiredFinalResultIsRejected() throws Exception {
        var clock = new AtomicLong();
        var metrics = new McpDiagnostics();
        var outer = new McpPagination.Budget(4, 4, 1024, 100, metrics, clock::get);
        var inner = new McpPagination.Budget(4, 4, 1024, 100, metrics, clock::get);
        McpPagination.enter(outer);
        McpPagination.enter(inner);
        assertNull(McpPagination.exit(inner, null));
        assertEquals(
                "ok",
                McpPagination.await(CompletableFuture.completedFuture("ok"), 1, TimeUnit.SECONDS));
        clock.set(100_000_000);
        assertEquals(
                "mcp-pagination-timeout",
                ((SecurityBlockedException) McpPagination.exit(outer, null)).ruleId());
        assertEquals(1, metrics.snapshot().paginationCompleted());
        assertEquals(1, metrics.snapshot().paginationFailed());
    }

    @Test
    void expiredBeforeWaitStillUsesTimeoutCancellationPath() {
        var clock = new AtomicLong();
        var metrics = new McpDiagnostics();
        var budget = new McpPagination.Budget(1, 1, 1024, 1, metrics, clock::get);
        var future =
                new CompletableFuture<String>() {
                    @Override
                    public String get(long timeout, TimeUnit unit) {
                        throw new AssertionError("Expired query must not wait");
                    }
                };
        McpPagination.enter(budget);
        clock.set(1_000_000);
        var failure =
                assertThrows(
                        TimeoutException.class,
                        () -> McpPagination.await(future, 1, TimeUnit.SECONDS));
        assertInstanceOf(SecurityBlockedException.class, McpPagination.exit(budget, failure));
    }

    @Test
    void interruptionRemainsOriginalFailureAndScopeIsCleaned() {
        var expected = new InterruptedException("fixture");
        var budget = new McpPagination.Budget(1, 1, 1024, new McpDiagnostics());
        var future =
                new CompletableFuture<String>() {
                    @Override
                    public String get(long timeout, TimeUnit unit) throws InterruptedException {
                        throw expected;
                    }
                };
        McpPagination.enter(budget);
        var failure =
                assertThrows(
                        InterruptedException.class,
                        () -> McpPagination.await(future, 1, TimeUnit.SECONDS));
        assertSame(expected, McpPagination.exit(budget, failure));
        assertThrows(
                SecurityBlockedException.class,
                () -> McpPagination.await(future, 1, TimeUnit.SECONDS));
    }

    @Test
    void pageLimitRejectsBeforeRequestFactoryAndCountsOnce() {
        var diagnostics = new McpDiagnostics();
        var budget = new McpPagination.Budget(2, 128, 1024, diagnostics);
        var calls = new AtomicInteger();
        var factory =
                McpPagination.requests((Long id, String cursor) -> calls.incrementAndGet(), budget);
        factory.apply(1L, null);
        budget.accept(1, budget.checkJson("{}"), "a");
        factory.apply(2L, "a");
        budget.accept(1, budget.checkJson("{}"), "b");
        assertEquals(
                "mcp-pagination-pages",
                assertThrows(SecurityBlockedException.class, () -> factory.apply(3L, "b"))
                        .ruleId());
        assertThrows(SecurityBlockedException.class, budget::request);
        budget.finish(false);
        budget.finish(false);
        assertEquals(2, calls.get());
        assertEquals(1, diagnostics.snapshot().limits().get(Limit.PAGINATION_PAGES));
        assertEquals(1, diagnostics.snapshot().paginationFailed());
    }

    @Test
    void rejectedPageNeverIncreasesAcceptedItems() {
        var diagnostics = new McpDiagnostics();
        var budget = new McpPagination.Budget(4, 2, 1024, diagnostics);
        budget.request();
        budget.accept(1, 2, "a");
        budget.request();
        assertEquals(
                "mcp-pagination-items",
                assertThrows(SecurityBlockedException.class, () -> budget.accept(2, 2, null))
                        .ruleId());
        budget.finish(false);
        assertEquals(1, diagnostics.snapshot().itemsAccepted());
        assertEquals(1, diagnostics.snapshot().pagesAccepted());
        assertEquals(1, diagnostics.snapshot().limits().get(Limit.PAGINATION_ITEMS));
    }

    @Test
    void utf8AggregateUsesBytesRatherThanCharactersAndAllowsExactBoundary() {
        var diagnostics = new McpDiagnostics();
        var budget = new McpPagination.Budget(4, 128, 10, diagnostics);
        budget.request();
        budget.accept(0, budget.checkJson("\"中\""), "a");
        budget.request();
        budget.accept(0, budget.checkJson("\"中\""), "b");
        budget.request();
        assertEquals(
                "mcp-pagination-bytes",
                assertThrows(SecurityBlockedException.class, () -> budget.checkJson("{}"))
                        .ruleId());
        budget.finish(false);
        assertEquals(10, diagnostics.snapshot().jsonBytesAccepted());
        var next = new McpPagination.Budget(1, 1, 6, diagnostics);
        next.request();
        next.accept(0, next.checkJson("\"😀\""), null);
        next.finish(true);
        assertEquals(1, diagnostics.snapshot().paginationCompleted());
    }

    @Test
    void repeatedOrOversizeCursorIsRejectedWithoutLeakingIt() {
        var diagnostics = new McpDiagnostics();
        var budget = new McpPagination.Budget(4, 4, 1024, diagnostics);
        budget.request();
        budget.accept(1, 2, "sensitive-cursor");
        budget.request();
        assertEquals(
                "mcp-pagination-cursor",
                assertThrows(
                                SecurityBlockedException.class,
                                () -> budget.accept(1, 2, "sensitive-cursor"))
                        .ruleId());
        budget.finish(false);
        assertFalse(diagnostics.snapshot().toString().contains("sensitive-cursor"));
        var other = new McpPagination.Budget(1, 1, 1024, diagnostics);
        other.request();
        assertThrows(SecurityBlockedException.class, () -> other.accept(0, 2, "x".repeat(1025)));
        other.finish(false);
        assertEquals(2, diagnostics.snapshot().limits().get(Limit.PAGINATION_CURSOR));
    }

    @Test
    void malformedInputAndNonLimitFailureDoNotCountAsCapacityRejection() {
        var diagnostics = new McpDiagnostics();
        var budget = new McpPagination.Budget(1, 1, 10, diagnostics);
        budget.request();
        assertEquals(
                "mcp-pagination-shape",
                assertThrows(SecurityBlockedException.class, () -> budget.checkJson("\ud800"))
                        .ruleId());
        budget.finish(false);
        assertEquals(1, diagnostics.snapshot().paginationFailed());
        assertEquals(
                0L,
                diagnostics.snapshot().limits().values().stream().mapToLong(Long::longValue).sum());
    }

    @Test
    void invalidConfigurationCannotReplaceTheExistingBudget() {
        var properties = new Properties();
        properties.setProperty("mcp.pagination.max.pages", "0");
        assertThrows(IllegalArgumentException.class, () -> McpPagination.initialize(properties));
        properties.clear();
        properties.setProperty("mcp.pagination.max.items", "129");
        assertThrows(IllegalArgumentException.class, () -> McpPagination.initialize(properties));
        properties.clear();
        properties.setProperty("mcp.pagination.timeout.ms", "0");
        assertThrows(IllegalArgumentException.class, () -> McpPagination.initialize(properties));
        properties.setProperty("mcp.pagination.timeout.ms", "300001");
        assertThrows(IllegalArgumentException.class, () -> McpPagination.initialize(properties));
        McpPagination.initialize(new Properties());
    }
}
