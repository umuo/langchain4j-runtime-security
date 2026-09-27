package io.agentsecurity.agent.stream;

import static org.junit.jupiter.api.Assertions.*;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.data.message.*;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.*;
import io.agentsecurity.agent.bridge.Bridge;
import io.agentsecurity.core.LocalPolicy;
import io.agentsecurity.core.PolicyEngine;
import io.agentsecurity.core.SecurityBlockedException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class GuardedPublisherTest {

    static final ChatRequest REQUEST =
            ChatRequest.builder().messages(UserMessage.from("hello")).build();

    static final CompleteResponse FINAL =
            new CompleteResponse(ChatResponse.builder().aiMessage(AiMessage.from("safe")).build());

    @BeforeEach
    void configure() {
        Properties policy = new Properties();
        policy.setProperty("deny.text", "secret");
        policy.setProperty("deny.tools", "sendEmail");
        Bridge.initialize(
                new PolicyEngine(List.of(new LocalPolicy(policy)), (event, decision) -> {}), 1000);
        GuardedStream.initialize(new StreamLimits(256, 128, 4, 800));
    }

    static class Collector implements Flow.Subscriber<Object> {

        final List<Object> events = new CopyOnWriteArrayList<>();

        final CompletableFuture<Throwable> terminal = new CompletableFuture<>();

        final AtomicInteger endings = new AtomicInteger();

        Flow.Subscription subscription;

        @Override
        public void onSubscribe(Flow.Subscription value) {
            subscription = value;
        }

        @Override
        public void onNext(Object event) {
            events.add(event);
        }

        @Override
        public void onError(Throwable error) {
            endings.incrementAndGet();
            terminal.complete(error);
        }

        @Override
        public void onComplete() {
            endings.incrementAndGet();
            terminal.complete(null);
        }

        String reason() throws Exception {
            return ((SecurityBlockedException) terminal.get(3, TimeUnit.SECONDS)).ruleId();
        }
    }

    static class Source implements Flow.Publisher<Object> {

        Flow.Subscriber<? super Object> consumer;

        final AtomicInteger starts = new AtomicInteger(), cancellations = new AtomicInteger();

        @Override
        public void subscribe(Flow.Subscriber<? super Object> subscriber) {
            starts.incrementAndGet();
            consumer = subscriber;
            subscriber.onSubscribe(
                    new Flow.Subscription() {

                        @Override
                        public void request(long count) {}

                        @Override
                        public void cancel() {
                            cancellations.incrementAndGet();
                        }
                    });
        }

        void emit(Object event) {
            consumer.onNext(event);
        }

        void finish() {
            emit(FINAL);
            consumer.onComplete();
        }
    }

    Collector protect(Source source) {
        Collector collector = new Collector();
        new GuardedPublisher(REQUEST, source).subscribe(collector);
        return collector;
    }

    @Test
    void releaseRequiresBothValidationAndDownstreamDemand() throws Exception {
        Source source = new Source();
        Collector collector = protect(source);
        collector.subscription.request(1);
        var first = new PartialResponse("hel");
        var second = new PartialResponse("lo");
        source.emit(first);
        source.emit(second);
        source.emit(FINAL);
        // Even the final event is not enough: upstream must terminate correctly.
        assertTrue(collector.events.isEmpty());
        source.consumer.onComplete();
        assertEquals(List.of(first), collector.events);
        assertFalse(collector.terminal.isDone());
        collector.subscription.request(1);
        assertEquals(List.of(first, second), collector.events);
        collector.subscription.request(1);
        assertEquals(List.of(first, second, FINAL), collector.events);
        assertNull(collector.terminal.get(1, TimeUnit.SECONDS));
        assertEquals(1, collector.endings.get());
        source.consumer.onError(new IllegalStateException());
        source.consumer.onComplete();
        assertEquals(1, collector.endings.get());
    }

    @Test
    void coldSubscriptionsAreIndependentAndInputDenialHasNoSideEffects() throws Exception {
        Source source = new Source();
        var publisher = new GuardedPublisher(REQUEST, source);
        assertEquals(0, source.starts.get());
        for (int i = 0; i < 2; i++) {
            Collector collector = new Collector();
            publisher.subscribe(collector);
            collector.subscription.request(Long.MAX_VALUE);
            source.finish();
            assertNull(collector.terminal.get(1, TimeUnit.SECONDS));
        }
        assertEquals(2, source.starts.get());
        Source denied = new Source();
        Collector collector = new Collector();
        new GuardedPublisher(
                        ChatRequest.builder().messages(UserMessage.from("secret")).build(), denied)
                .subscribe(collector);
        assertEquals("denied-text", collector.reason());
        assertEquals(0, denied.starts.get());
    }

    @Test
    void splitTextAndThinkingCannotHideBehindSafeFinalResponse() throws Exception {
        for (boolean thinking : List.of(false, true)) {
            Source source = new Source();
            Collector collector = protect(source);
            collector.subscription.request(Long.MAX_VALUE);
            source.emit(thinking ? new PartialThinking("sec") : new PartialResponse("sec"));
            source.emit(thinking ? new PartialThinking("ret") : new PartialResponse("ret"));
            source.finish();
            assertEquals("denied-text", collector.reason());
            assertTrue(collector.events.isEmpty());
            assertTrue(source.cancellations.get() > 0);
        }
    }

    @Test
    void completeToolsAndSplitArgumentsAreValidatedBeforeRelease() throws Exception {
        Source source = new Source();
        Collector collector = protect(source);
        collector.subscription.request(Long.MAX_VALUE);
        source.emit(
                new CompleteToolCall(
                        0,
                        ToolExecutionRequest.builder()
                                .id("id")
                                .name("sendEmail")
                                .arguments("{}")
                                .build()));
        source.finish();
        assertEquals("denied-tool", collector.reason());
        assertTrue(collector.events.isEmpty());
        Source split = new Source();
        Collector other = protect(split);
        other.subscription.request(Long.MAX_VALUE);
        split.emit(PartialToolCall.builder().index(0).name("read").partialArguments("sec").build());
        split.emit(PartialToolCall.builder().index(0).name("read").partialArguments("ret").build());
        split.finish();
        assertEquals("denied-text", other.reason());
        assertTrue(other.events.isEmpty());
    }

    @Test
    void malformedSequencesAndUnknownEventTypesFailClosed() throws Exception {
        Source missing = new Source();
        Collector first = protect(missing);
        missing.consumer.onComplete();
        assertEquals("missing-stream-response", first.reason());
        Source late = new Source();
        Collector second = protect(late);
        late.emit(FINAL);
        late.emit(new PartialResponse("late"));
        assertEquals("stream-event-order", second.reason());
        assertTrue(second.events.isEmpty());
        Source unknown = new Source();
        Collector third = protect(unknown);
        unknown.emit(new Object());
        assertEquals("unsupported-stream-event", third.reason());
    }

    @Test
    void characterAndEventCountsAreBounded() throws Exception {
        Source oversized = new Source();
        Collector first = protect(oversized);
        oversized.emit(new PartialResponse("x".repeat(257)));
        assertEquals("stream-buffer-limit", first.reason());
        Source many = new Source();
        Collector second = protect(many);
        for (int i = 0; i < 129; i++) {
            many.emit(new PartialResponse("x"));
        }
        assertEquals("stream-buffer-limit", second.reason());
        assertTrue(second.events.isEmpty());
    }

    @Test
    void cancellationInOnSubscribeDoesNotStartUpstream() {
        Source source = new Source();
        Collector collector =
                new Collector() {

                    @Override
                    public void onSubscribe(Flow.Subscription subscription) {
                        super.onSubscribe(subscription);
                        subscription.cancel();
                    }
                };
        new GuardedPublisher(REQUEST, source).subscribe(collector);
        assertEquals(0, source.starts.get());
        assertFalse(collector.terminal.isDone());
    }

    @Test
    void cancellingAnActiveStreamPropagatesUpstreamAndDropsBufferedEvents() {
        Source source = new Source();
        Collector collector = protect(source);
        source.emit(new PartialResponse("safe"));
        collector.subscription.cancel();
        source.finish();
        assertTrue(source.cancellations.get() > 0);
        assertTrue(collector.events.isEmpty());
        assertFalse(collector.terminal.isDone());
    }

    @Test
    void invalidDemandSignalsExactlyOneErrorWithoutStartingSource() throws Exception {
        Source source = new Source();
        Collector collector =
                new Collector() {

                    @Override
                    public void onSubscribe(Flow.Subscription subscription) {
                        super.onSubscribe(subscription);
                        subscription.request(0);
                    }
                };
        new GuardedPublisher(REQUEST, source).subscribe(collector);
        assertInstanceOf(
                IllegalArgumentException.class, collector.terminal.get(1, TimeUnit.SECONDS));
        collector.subscription.request(-1);
        assertEquals(1, collector.endings.get());
        assertEquals(0, source.starts.get());
    }

    @Test
    void noDemandTimesOutAndCapacityIncludesCompletedUndeliveredStreams() throws Exception {
        List<Collector> held = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            Source source = new Source();
            held.add(protect(source));
            source.finish();
        }
        Source refused = new Source();
        Collector excess = protect(refused);
        assertEquals("stream-capacity", excess.reason());
        assertEquals(0, refused.starts.get());
        for (Collector collector : held) {
            assertEquals("stream-timeout", collector.reason());
            assertTrue(collector.events.isEmpty());
        }
        Source recovered = new Source();
        Collector next = protect(recovered);
        next.subscription.request(Long.MAX_VALUE);
        recovered.finish();
        assertNull(next.terminal.get(1, TimeUnit.SECONDS));
    }

    @Test
    void callbackAndReactivePathsShareTheSameCapacity() throws Exception {
        List<Collector> held = new ArrayList<>();
        try {
            for (int i = 0; i < 4; i++) {
                held.add(protect(new Source()));
            }
            assertEquals(
                    "stream-capacity",
                    assertThrows(
                                    SecurityBlockedException.class,
                                    () ->
                                            GuardedStream.wrap(
                                                    REQUEST,
                                                    new StreamingChatResponseHandler() {

                                                        @Override
                                                        public void onCompleteResponse(
                                                                ChatResponse response) {}

                                                        @Override
                                                        public void onError(Throwable error) {}
                                                    }))
                            .ruleId());
        } finally {
            held.forEach(c -> c.subscription.cancel());
        }
    }

    @Test
    void downstreamThrowCancelsWithoutSecondSignalAndReleasesCapacity() {
        for (int i = 0; i < 8; i++) {
            Source source = new Source();
            Collector collector =
                    new Collector() {

                        @Override
                        public void onNext(Object event) {
                            throw new IllegalStateException("subscriber failed");
                        }
                    };
            new GuardedPublisher(REQUEST, source).subscribe(collector);
            collector.subscription.request(Long.MAX_VALUE);
            source.finish();
            assertTrue(source.cancellations.get() > 0);
            assertEquals(0, collector.endings.get());
        }
    }

    @Test
    void concurrentAndReentrantDemandNeverDuplicatesEventsOrSignals() throws Exception {
        Source source = new Source();
        Collector collector = protect(source);
        for (int i = 0; i < 100; i++) {
            source.emit(new PartialResponse("x"));
        }
        source.finish();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < 101; i++) {
                futures.add(pool.submit(() -> collector.subscription.request(1)));
            }
            for (var future : futures) {
                future.get(1, TimeUnit.SECONDS);
            }
            assertNull(collector.terminal.get(1, TimeUnit.SECONDS));
            assertEquals(101, collector.events.size());
            assertEquals(1, collector.endings.get());
        } finally {
            pool.shutdownNow();
        }
        Source reentrant = new Source();
        Collector other =
                new Collector() {

                    @Override
                    public void onNext(Object event) {
                        super.onNext(event);
                        subscription.request(1);
                    }
                };
        new GuardedPublisher(REQUEST, reentrant).subscribe(other);
        other.subscription.request(1);
        reentrant.emit(new PartialResponse("hello"));
        reentrant.finish();
        assertNull(other.terminal.get(1, TimeUnit.SECONDS));
        assertEquals(2, other.events.size());
    }

    @Test
    void recognizedRawControlIsAllowedButEscapedContentAndUnknownPayloadAreDenied()
            throws Exception {
        Source safe = new Source();
        Collector collector = protect(safe);
        collector.subscription.request(Long.MAX_VALUE);
        safe.emit(
                RawStreamingEvent.of(
                        new dev.langchain4j.http.client.sse.ServerSentEvent(null, "[DONE]")));
        safe.finish();
        assertNull(collector.terminal.get(1, TimeUnit.SECONDS));
        assertEquals(2, collector.events.size());
        Source unsafe = new Source();
        Collector other = protect(unsafe);
        other.subscription.request(Long.MAX_VALUE);
        unsafe.emit(
                RawStreamingEvent.of(
                        new dev.langchain4j.http.client.sse.ServerSentEvent(
                                null,
                                "{\"id\":\"s\\u0065cret\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}")));
        assertEquals("denied-text", other.reason());
        assertTrue(other.events.isEmpty());
        Source unknown = new Source();
        Collector third = protect(unknown);
        unknown.emit(RawStreamingEvent.of("unchecked"));
        assertInstanceOf(SecurityBlockedException.class, third.terminal.get(1, TimeUnit.SECONDS));
    }

    @Test
    void sourceErrorsAndTimeoutsDiscardAllPendingContentAndCancel() throws Exception {
        Source error = new Source();
        Collector first = protect(error);
        first.subscription.request(Long.MAX_VALUE);
        error.emit(new PartialResponse("safe"));
        var problem = new IllegalStateException("source failed");
        error.consumer.onError(problem);
        assertSame(problem, first.terminal.get(1, TimeUnit.SECONDS));
        assertTrue(first.events.isEmpty());
        assertTrue(error.cancellations.get() > 0);
        Source stuck = new Source();
        Collector second = protect(stuck);
        second.subscription.request(Long.MAX_VALUE);
        stuck.emit(new PartialResponse("safe"));
        assertEquals("stream-timeout", second.reason());
        assertTrue(stuck.cancellations.get() > 0);
        assertTrue(second.events.isEmpty());
        stuck.finish();
        assertEquals(1, second.endings.get());
    }

    @Test
    void blockedOnNextNeverReceivesConcurrentTerminalAndDoesNotBlockOtherTimers() throws Exception {
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        Source first = new Source();
        Collector blocking =
                new Collector() {

                    @Override
                    public void onNext(Object event) {
                        super.onNext(event);
                        entered.countDown();
                        try {
                            release.await();
                        } catch (InterruptedException error) {
                            Thread.currentThread().interrupt();
                        }
                    }
                };
        ExecutorService provider = Executors.newSingleThreadExecutor();
        try {
            new GuardedPublisher(REQUEST, first).subscribe(blocking);
            blocking.subscription.request(Long.MAX_VALUE);
            Future<?> delivering = provider.submit(first::finish);
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            Source second = new Source();
            Collector independent = protect(second);
            assertEquals("stream-timeout", independent.reason());
            assertFalse(blocking.terminal.isDone());
            release.countDown();
            delivering.get(2, TimeUnit.SECONDS);
            assertEquals("stream-timeout", blocking.reason());
            assertEquals(1, blocking.endings.get());
        } finally {
            release.countDown();
            provider.shutdownNow();
        }
    }

    @Test
    void duplicateSubscriptionsAreCancelledAndProtocolViolationsFailClosed() throws Exception {
        Source source = new Source();
        Collector collector = protect(source);
        AtomicBoolean cancelled = new AtomicBoolean();
        source.consumer.onSubscribe(
                new Flow.Subscription() {

                    @Override
                    public void request(long count) {
                        fail("Duplicate subscription must not be requested");
                    }

                    @Override
                    public void cancel() {
                        cancelled.set(true);
                    }
                });
        assertTrue(cancelled.get());
        collector.subscription.request(Long.MAX_VALUE);
        source.finish();
        assertNull(collector.terminal.get(1, TimeUnit.SECONDS));
        Collector invalid = new Collector();
        new GuardedPublisher(REQUEST, downstream -> downstream.onNext(new PartialResponse("early")))
                .subscribe(invalid);
        assertEquals("stream-protocol-error", invalid.reason());
        assertTrue(invalid.events.isEmpty());
    }

    @Test
    void cancellationDuringDeliveryAndOverflowingDemandRemainBounded() throws Exception {
        Source source = new Source();
        Collector collector =
                new Collector() {

                    @Override
                    public void onNext(Object event) {
                        super.onNext(event);
                        subscription.cancel();
                    }
                };
        new GuardedPublisher(REQUEST, source).subscribe(collector);
        collector.subscription.request(Long.MAX_VALUE);
        collector.subscription.request(Long.MAX_VALUE);
        source.emit(new PartialResponse("hello"));
        source.finish();
        assertEquals(1, collector.events.size());
        assertFalse(collector.terminal.isDone());
        assertTrue(source.cancellations.get() > 0);
        Source allowed = new Source();
        Collector other = protect(allowed);
        other.subscription.request(Long.MAX_VALUE);
        other.subscription.request(Long.MAX_VALUE);
        allowed.finish();
        assertNull(other.terminal.get(1, TimeUnit.SECONDS));
        assertEquals(1, other.events.size());
    }
}
