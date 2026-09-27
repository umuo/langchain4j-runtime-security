package io.agentsecurity.agent;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.*;
import io.agentsecurity.core.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class GuardedStreamTest {
    static final ChatRequest REQUEST = ChatRequest.builder().messages(UserMessage.from("hello")).build();
    static final ChatResponse SAFE = ChatResponse.builder().aiMessage(AiMessage.from("safe")).build();

    @BeforeAll static void configure() {
        Properties policy = new Properties();
        policy.setProperty("deny.text", "secret"); policy.setProperty("deny.tools", "sendEmail");
        Bridge.initialize(new PolicyEngine(List.of(new LocalPolicy(policy)), (event, decision) -> {}), 1000);
        GuardedStream.initialize(new StreamLimits(64, 8, 4, 500));
    }

    static final class Collector implements StreamingChatResponseHandler {
        final List<String> events = new CopyOnWriteArrayList<>();
        final CompletableFuture<Throwable> terminal = new CompletableFuture<>();
        final AtomicInteger endings = new AtomicInteger();
        @Override public void onPartialResponse(String text) { events.add(text); }
        @Override public void onPartialThinking(PartialThinking thinking) { events.add(thinking.text()); }
        @Override public void onCompleteToolCall(CompleteToolCall call) { events.add("tool"); }
        @Override public void onCompleteResponse(ChatResponse result) { endings.incrementAndGet(); terminal.complete(null); }
        @Override public void onError(Throwable error) { endings.incrementAndGet(); terminal.complete(error); }
        Throwable failure() throws Exception { return terminal.get(3, TimeUnit.SECONDS); }
    }

    static StreamingChatResponseHandler protect(Collector collector) {
        return (StreamingChatResponseHandler) GuardedStream.wrap(REQUEST, collector);
    }

    @Test void validChunksAreHeldUntilValidationThenReplayedInOrder() throws Exception {
        Collector collector = new Collector(); var handler = protect(collector);
        handler.onPartialResponse("hel"); handler.onPartialResponse("lo");
        assertTrue(collector.events.isEmpty());
        handler.onCompleteResponse(SAFE);
        assertNull(collector.failure()); assertEquals(List.of("hel", "lo"), collector.events);
        handler.onError(new IllegalStateException()); handler.onCompleteResponse(SAFE);
        assertEquals(1, collector.endings.get());
    }

    @Test void splitForbiddenTextCannotHideBehindSafeFinalResponse() throws Exception {
        Collector collector = new Collector(); var handler = protect(collector);
        handler.onPartialResponse("sec"); handler.onPartialResponse("ret"); handler.onCompleteResponse(SAFE);
        assertInstanceOf(SecurityBlockedException.class, collector.failure()); assertTrue(collector.events.isEmpty());
    }

    @Test void thinkingIsAlsoCheckedAcrossChunks() throws Exception {
        Collector collector = new Collector(); var handler = protect(collector);
        handler.onPartialThinking(new PartialThinking("sec")); handler.onPartialThinking(new PartialThinking("ret"));
        handler.onCompleteResponse(SAFE);
        assertInstanceOf(SecurityBlockedException.class, collector.failure()); assertTrue(collector.events.isEmpty());
    }

    @Test void completeToolCallbackCannotExecuteBeforeValidation() throws Exception {
        Collector collector = new Collector(); var handler = protect(collector);
        handler.onCompleteToolCall(new CompleteToolCall(0,
                ToolExecutionRequest.builder().id("one").name("sendEmail").arguments("{}").build()));
        assertTrue(collector.events.isEmpty()); handler.onCompleteResponse(SAFE);
        assertEquals("denied-tool", ((SecurityBlockedException) collector.failure()).ruleId()); assertTrue(collector.events.isEmpty());
    }

    @Test void oversizedAndExcessiveEventsAreRefused() throws Exception {
        Collector big = new Collector(); var handler = protect(big);
        handler.onPartialResponse("x".repeat(65));
        assertEquals("stream-buffer-limit", ((SecurityBlockedException) big.failure()).ruleId());
        assertTrue(big.events.isEmpty());
        Collector many = new Collector(); var other = protect(many);
        for (int i = 0; i < 9; i++) other.onPartialResponse("x");
        assertInstanceOf(SecurityBlockedException.class, many.failure()); assertTrue(many.events.isEmpty());
    }

    @Test void timeoutDiscardsAllBufferedOutputAndReleasesCapacity() throws Exception {
        Collector collector = new Collector(); var handler = protect(collector);
        handler.onPartialResponse("held");
        assertEquals("stream-timeout", ((SecurityBlockedException) collector.failure()).ruleId());
        handler.onCompleteResponse(SAFE); assertTrue(collector.events.isEmpty()); assertEquals(1, collector.endings.get());
    }

    @Test void concurrencyIsBoundedAndAbortedStreamsReleasePermits() throws Exception {
        var handlers = new java.util.ArrayList<StreamingChatResponseHandler>();
        try {
            for (int i = 0; i < 4; i++) handlers.add(protect(new Collector()));
            assertEquals("stream-capacity", assertThrows(SecurityBlockedException.class,
                    () -> protect(new Collector())).ruleId());
        } finally { handlers.forEach(GuardedStream::abort); }
        Collector collector = new Collector(); protect(collector).onCompleteResponse(SAFE);
        assertNull(collector.failure());
    }

    @Test void upstreamFailureDoesNotReleasePartialData() throws Exception {
        Collector collector = new Collector(); var handler = protect(collector);
        handler.onPartialResponse("held"); var error = new IllegalStateException("upstream");
        handler.onError(error); handler.onCompleteResponse(SAFE);
        assertSame(error, collector.failure()); assertTrue(collector.events.isEmpty()); assertEquals(1, collector.endings.get());
    }

    @Test void unknownRawEventsFailClosed() throws Exception {
        Collector collector = new Collector(); var handler = protect(collector);
        handler.onUnmappedRawEvent("unchecked");
        assertEquals("unsupported-stream-event", ((SecurityBlockedException) collector.failure()).ruleId());
    }

    @Test void recognizedRawControlStillRejectsEscapedSecretsAndDuplicateKeys() {
        String safe = "{\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}";
        var event = new dev.langchain4j.http.client.sse.ServerSentEvent(null, safe);
        assertEquals(safe, RawStreamControl.inspect(REQUEST, event, 1000));
        for (String unsafe : List.of("{\"choices\":[],\"id\":\"\\u0073ecret\"}",
                "{\"choices\":[],\"choices\":[]}", "{\"choices\":[],\"unknown\":1}",
                "{\"choices\":[{\"index\":0,\"delta\":{\"content\":\"unmapped text\"}}]}")) {
            assertThrows(SecurityBlockedException.class, () -> RawStreamControl.inspect(REQUEST,
                    new dev.langchain4j.http.client.sse.ServerSentEvent(null, unsafe), 1000));
        }
    }

    @Test void toolArgumentsAreReconstructedAcrossChunks() throws Exception {
        Collector collector = new Collector(); var handler = protect(collector);
        handler.onPartialToolCall(PartialToolCall.builder().index(0).name("read").partialArguments("sec").build());
        handler.onPartialToolCall(PartialToolCall.builder().index(0).name("read").partialArguments("ret").build());
        handler.onCompleteResponse(SAFE);
        assertInstanceOf(SecurityBlockedException.class, collector.failure()); assertTrue(collector.events.isEmpty());
    }

    @Test void oversizedFirstTypedChunkCancelsUpstream() throws Exception {
        AtomicInteger cancelled = new AtomicInteger();
        StreamingHandle handle = new StreamingHandle() {
            @Override public void cancel() { cancelled.incrementAndGet(); }
            @Override public boolean isCancelled() { return cancelled.get() > 0; }
        };
        Collector collector = new Collector(); var handler = protect(collector);
        handler.onPartialResponse(new PartialResponse("x".repeat(65)), new PartialResponseContext(handle));
        assertInstanceOf(SecurityBlockedException.class, collector.failure()); assertEquals(1, cancelled.get());
        assertTrue(collector.events.isEmpty());
    }

    @Test void consumerFailureReleasesCapacityWithoutDoubleTerminal() {
        var consumer = new StreamingChatResponseHandler() {
            @Override public void onPartialResponse(String text) { throw new IllegalArgumentException("consumer failure"); }
            @Override public void onCompleteResponse(ChatResponse response) { fail("Consumer already failed"); }
            @Override public void onError(Throwable error) { fail("Do not call consumer twice"); }
        };
        var handler = (StreamingChatResponseHandler) GuardedStream.wrap(REQUEST, consumer);
        handler.onPartialResponse("held");
        assertThrows(IllegalArgumentException.class, () -> handler.onCompleteResponse(SAFE));
        handler.onError(new IllegalStateException());
    }
}
