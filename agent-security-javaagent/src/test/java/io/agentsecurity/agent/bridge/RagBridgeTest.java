package io.agentsecurity.agent.bridge;

import static org.junit.jupiter.api.Assertions.*;

import dev.langchain4j.data.document.Metadata;
import dev.langchain4j.data.segment.TextSegment;
import dev.langchain4j.rag.content.Content;
import dev.langchain4j.rag.content.retriever.ContentRetriever;
import dev.langchain4j.rag.query.Query;
import io.agentsecurity.core.LocalPolicy;
import io.agentsecurity.core.PolicyEngine;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import io.agentsecurity.core.SecurityEvent;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.*;

class RagBridgeTest {

    PolicyEngine engine;

    final List<SecurityEvent> events = new CopyOnWriteArrayList<>();

    final Query query = Query.from("lookup");

    @BeforeEach
    void configure() {
        Properties properties = new Properties();
        properties.setProperty("deny.text", "SECRET_MARKER");
        engine =
                new PolicyEngine(
                        List.of(new LocalPolicy(properties)),
                        (event, decision) -> events.add(event));
        Bridge.initialize(engine, 1000);
        RagBridge.initialize(new Properties());
    }

    @AfterEach
    void close() {
        engine.close();
    }

    @Test
    void metadataIsUntrustedTextAndNeverBecomesIdentity() {
        var source = (ContentRetriever) q -> List.of();
        assertEquals(
                "denied-text",
                assertThrows(
                                SecurityBlockedException.class,
                                () ->
                                        RagBridge.after(
                                                source,
                                                query,
                                                "retrieve",
                                                List.of(
                                                        Content.from(
                                                                TextSegment.from(
                                                                        "safe",
                                                                        Metadata.from(
                                                                                "source",
                                                                                "SECRET_MARKER"))))))
                        .ruleId());
        assertNull(events.get(0).context());
    }

    @Test
    void validatesEntireBatchBeforeReturningAndBoundsCombinedText() {
        ContentRetriever source = q -> List.of(Content.from("safe"), Content.from("SECRET_MARKER"));
        var guarded = (ContentRetriever) RagBridge.wrap(source, RagBridge.RETRIEVER, "retrieve");
        assertEquals(
                "denied-text",
                assertThrows(SecurityBlockedException.class, () -> guarded.retrieve(query))
                        .ruleId());
        assertEquals(
                "text-limit",
                assertThrows(
                                SecurityBlockedException.class,
                                () ->
                                        RagBridge.after(
                                                source,
                                                query,
                                                "retrieve",
                                                List.of(
                                                        Content.from("x".repeat(600)),
                                                        Content.from("y".repeat(600)))))
                        .ruleId());
    }

    @Test
    void resultCountsAndMetadataEntriesAreBoundedEvenWithShortText() {
        Properties limits = new Properties();
        limits.setProperty("rag.max.contents", "2");
        limits.setProperty("rag.max.metadata.entries", "1");
        RagBridge.initialize(limits);
        assertEquals(
                "rag-content-limit",
                assertThrows(
                                SecurityBlockedException.class,
                                () ->
                                        RagBridge.after(
                                                this,
                                                query,
                                                "retrieve",
                                                List.of(
                                                        Content.from("a"),
                                                        Content.from("b"),
                                                        Content.from("c"))))
                        .ruleId());
        assertEquals(
                "rag-content-limit",
                assertThrows(
                                SecurityBlockedException.class,
                                () ->
                                        RagBridge.after(
                                                this,
                                                query,
                                                "retrieve",
                                                List.of(
                                                        Content.from(
                                                                TextSegment.from(
                                                                        "a",
                                                                        Metadata.from("a", "1")
                                                                                .put("b", "2"))))))
                        .ruleId());
    }

    @Test
    void invalidShapeAndNullFutureFailClosed() {
        assertEquals(
                "adapter-shape-error",
                assertThrows(
                                SecurityBlockedException.class,
                                () ->
                                        RagBridge.after(
                                                this,
                                                query,
                                                "retrieve",
                                                Arrays.asList((Object) null)))
                        .ruleId());
        assertEquals(
                "null-result",
                assertThrows(
                                SecurityBlockedException.class,
                                () -> RagBridge.after(this, query, "retrieve", null))
                        .ruleId());
        var result = RagBridge.guardFuture(this, query, "retrieveAsync", null, null);
        assertInstanceOf(
                SecurityBlockedException.class,
                assertThrows(CompletionException.class, result::join).getCause());
    }

    @Test
    void rejectionPrecedesLambdaSideEffectAndWrappingIsIdempotent() {
        AtomicInteger calls = new AtomicInteger();
        ContentRetriever source =
                q -> {
                    calls.incrementAndGet();
                    return List.of();
                };
        var guarded = (ContentRetriever) RagBridge.wrap(source, RagBridge.RETRIEVER, "retrieve");
        assertSame(guarded, RagBridge.wrap(guarded, RagBridge.RETRIEVER, "retrieve"));
        assertThrows(
                SecurityBlockedException.class,
                () -> guarded.retrieve(Query.from("SECRET_MARKER")));
        assertEquals(0, calls.get());
    }

    @Test
    void cancellationPropagatesAndCompletionRestoresForeignIdentity() {
        SecurityContext origin = SecurityContext.authenticated("tenant-a", "user-a", Set.of());
        SecurityContext foreign = SecurityContext.authenticated("tenant-b", "user-b", Set.of());
        var source = new CompletableFuture<List<Content>>();
        var guarded = RagBridge.guardFuture(this, query, "retrieveAsync", source, origin);
        AtomicReference<SecurityContext> callback = new AtomicReference<>();
        var next = guarded.thenRun(() -> callback.set(SecurityContexts.current()));
        try (var scope = SecurityContexts.open(foreign)) {
            source.complete(List.of(Content.from("safe")));
            assertSame(foreign, SecurityContexts.current());
        }
        next.join();
        assertSame(origin, callback.get());
        assertSame(origin, events.get(0).context());
        assertNull(SecurityContexts.current());
        var pending = new CompletableFuture<List<Content>>();
        RagBridge.guardFuture(this, query, "retrieveAsync", pending, origin).cancel(true);
        assertTrue(pending.isCancelled());
    }

    @Test
    void retrieverAllowlistIsClosedAndDoesNotAffectOtherPhases() {
        Properties p = new Properties();
        p.setProperty("allow.retrievers", "trusted.Retriever");
        var policy = new LocalPolicy(p);
        assertTrue(
                policy.evaluate(
                                new SecurityEvent(
                                        SecurityEvent.Phase.RETRIEVAL_INPUT,
                                        "trusted.Retriever",
                                        "query"))
                        .allowed());
        assertEquals(
                "retriever-not-allowed",
                policy.evaluate(
                                new SecurityEvent(
                                        SecurityEvent.Phase.RETRIEVAL_INPUT,
                                        "other.Retriever",
                                        "query"))
                        .ruleId());
        assertTrue(
                policy.evaluate(new SecurityEvent(SecurityEvent.Phase.MODEL_INPUT, "chat", "query"))
                        .allowed());
        p.setProperty("allow.retrievers", "");
        assertFalse(
                new LocalPolicy(p)
                        .evaluate(
                                new SecurityEvent(
                                        SecurityEvent.Phase.RETRIEVAL_INPUT,
                                        "trusted.Retriever",
                                        "query"))
                        .allowed());
    }

    @Test
    void invalidLimitsFailAtInitialization() {
        for (String key : List.of("rag.max.contents", "rag.max.metadata.entries")) {
            Properties properties = new Properties();
            properties.setProperty(key, "0");
            assertThrows(IllegalArgumentException.class, () -> RagBridge.initialize(properties));
        }
    }
}
