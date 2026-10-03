package io.agentsecurity.agent.bridge;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.*;
import io.agentsecurity.core.diagnostics.*;
import java.util.Set;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;

class McpFailureBridgeTest {
    @Test
    void asyncFailureIsRecordedBeforeDeliveryUsingCapturedContext() {
        FailureDiagnostics.global().drain(65536);
        var captured = SecurityContext.authenticated("tenant", "original", Set.of());
        var other = SecurityContext.authenticated("tenant", "worker", Set.of());
        var source = new CompletableFuture<Object>();
        var guarded = McpBridge.guardFuture(null, null, "not-retained", source, captured);
        try (var scope = SecurityContexts.open(other)) {
            source.completeExceptionally(new IllegalStateException("secret-credentials"));
            assertThrows(CompletionException.class, guarded::join);
        }
        var records = FailureDiagnostics.global().drain(65536);
        assertEquals(1, records.size());
        assertEquals(captured.runId(), records.get(0).runId());
        assertEquals(FailureRecord.Stage.MCP_EXECUTION, records.get(0).stage());
        assertEquals(FailureRecord.Boundary.MCP_TOOL, records.get(0).boundary());
        assertNull(records.get(0).phase());
        assertFalse(records.toString().contains("secret"));
    }

    @Test
    void asyncCancellationStillReachesTheSource() {
        var source = new CompletableFuture<Object>();
        var guarded = McpBridge.guardFuture(null, null, "not-retained", source, null);
        assertTrue(guarded.cancel(true));
        assertTrue(source.isCancelled());
    }
}
