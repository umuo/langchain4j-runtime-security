package io.agentsecurity.core;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.health.McpDiagnostics;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;

class McpDiagnosticsTest {
    @Test
    void concurrentDiagnosticsKeepFixedDimensionsAndImmutableSnapshots() throws Exception {
        var diagnostics = new McpDiagnostics();
        var pool = Executors.newFixedThreadPool(4);
        try {
            var tasks = new java.util.ArrayList<Future<?>>();
            for (int i = 0; i < 100; i++) {
                tasks.add(
                        pool.submit(
                                () -> {
                                    diagnostics.paginationStarted();
                                    diagnostics.pageRequested();
                                    diagnostics.pageAccepted(2, 32);
                                    diagnostics.paginationFinished(true);
                                    diagnostics.limit(McpDiagnostics.Limit.HTTP_RESPONSE_BYTES);
                                }));
            }
            for (var task : tasks) {
                task.get(5, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        var snapshot = diagnostics.snapshot();
        assertEquals(100, snapshot.paginationCompleted());
        assertEquals(200, snapshot.itemsAccepted());
        assertEquals(3200, snapshot.jsonBytesAccepted());
        assertEquals(McpDiagnostics.Limit.values().length, snapshot.limits().size());
        assertThrows(UnsupportedOperationException.class, () -> snapshot.limits().clear());
    }
}
