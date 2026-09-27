package io.agentsecurity.agent;

import dev.langchain4j.data.message.*;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.*;
import io.agentsecurity.core.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class ContextPropagationTest {
    static final SecurityContext A = SecurityContext.authenticated("tenant-a", "user-a", Set.of());
    static final SecurityContext B = SecurityContext.authenticated("tenant-b", "user-b", Set.of());
    static final ChatRequest REQUEST = ChatRequest.builder().messages(UserMessage.from("hello")).build();
    static final ChatResponse RESPONSE = ChatResponse.builder().aiMessage(AiMessage.from("safe")).build();
    final List<SecurityEvent> events = new CopyOnWriteArrayList<>();

    @BeforeEach void configure() {
        Bridge.initialize(new PolicyEngine(List.of(), (event, decision) -> events.add(event)), 1000);
        GuardedStream.initialize(new StreamLimits(1000, 16, 4, 1000));
    }

    @ParameterizedTest @ValueSource(booleans = {true, false})
    void futureOutputAndContinuationUseCapturedIdentityEvenOnForeignWorker(boolean authenticated) {
        SecurityContext expected = authenticated ? A : null;
        var source = new CompletableFuture<ChatResponse>(); CompletableFuture<?> guarded;
        try (var scope = SecurityContexts.restore(expected)) { guarded = Bridge.guardFuture(REQUEST, source); }
        AtomicReference<SecurityContext> observed = new AtomicReference<>(B);
        var continuation = guarded.thenRun(() -> observed.set(SecurityContexts.current()));
        try (var scope = SecurityContexts.open(B)) { source.complete(RESPONSE); assertSame(B, SecurityContexts.current()); }
        continuation.join(); assertSame(expected, observed.get()); assertSame(expected, events.get(0).context());
        assertNull(SecurityContexts.current());
    }

    @ParameterizedTest @ValueSource(booleans = {true, false})
    void streamOutputAndSubscriberExceptionsCannotLeakWorkerIdentity(boolean authenticated) {
        SecurityContext expected = authenticated ? A : null;
        AtomicReference<SecurityContext> observed = new AtomicReference<>(B);
        StreamingChatResponseHandler guarded;
        try (var scope = SecurityContexts.restore(expected)) {
            guarded = (StreamingChatResponseHandler) Bridge.guardStream(REQUEST, new StreamingChatResponseHandler() {
                @Override public void onCompleteResponse(ChatResponse response) { observed.set(SecurityContexts.current()); throw new IllegalStateException("consumer failed"); }
                @Override public void onError(Throwable error) { fail("A second terminal callback is forbidden"); }
            });
        }
        try (var scope = SecurityContexts.open(B)) {
            assertThrows(IllegalStateException.class, () -> guarded.onCompleteResponse(RESPONSE));
            assertSame(B, SecurityContexts.current());
        }
        assertSame(expected, observed.get()); assertSame(expected, events.get(0).context()); assertNull(SecurityContexts.current());
    }

    @ParameterizedTest @ValueSource(booleans = {true, false})
    void exceptionalFutureCompletionRestoresScopeAfterUserErrorHandler(boolean authenticated) {
        SecurityContext expected = authenticated ? A : null;
        var source = new CompletableFuture<ChatResponse>(); CompletableFuture<?> guarded;
        try (var scope = SecurityContexts.restore(expected)) { guarded = Bridge.guardFuture(REQUEST, source); }
        var observed = new AtomicReference<SecurityContext>(B);
        var callback = guarded.handle((value, error) -> { observed.set(SecurityContexts.current()); throw new IllegalStateException("handler failed"); });
        try (var scope = SecurityContexts.open(B)) { source.completeExceptionally(new IllegalStateException("provider failed")); assertSame(B, SecurityContexts.current()); }
        assertThrows(CompletionException.class, callback::join); assertSame(expected, observed.get()); assertNull(SecurityContexts.current());
    }

    @ParameterizedTest @ValueSource(booleans = {true, false})
    void reactiveSignalsKeepTheOriginSnapshotIncludingAbsentIdentity(boolean authenticated) {
        SecurityContext expected = authenticated ? A : null;
        AtomicReference<Flow.Subscriber<? super Object>> receiver = new AtomicReference<>();
        Flow.Publisher<Object> source = subscriber -> {
            receiver.set(subscriber);
            subscriber.onSubscribe(new Flow.Subscription() {
                @Override public void request(long count) { }
                @Override public void cancel() { }
            });
        };
        Flow.Publisher<?> guarded;
        try (var scope = SecurityContexts.restore(expected)) { guarded = Bridge.guardPublisher(REQUEST, source); }
        AtomicReference<SecurityContext> observed = new AtomicReference<>(B);
        CompletableFuture<Void> done = new CompletableFuture<>();
        guarded.subscribe(new Flow.Subscriber<Object>() {
            @Override public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
            @Override public void onNext(Object item) { observed.set(SecurityContexts.current()); }
            @Override public void onError(Throwable error) { done.completeExceptionally(error); }
            @Override public void onComplete() { done.complete(null); }
        });
        try (var scope = SecurityContexts.open(B)) {
            receiver.get().onNext(new CompleteResponse(RESPONSE)); receiver.get().onComplete();
            assertSame(B, SecurityContexts.current());
        }
        done.join(); assertSame(expected, observed.get()); assertTrue(events.stream().allMatch(event -> event.context() == expected));
    }
}
