package io.agentsecurity.agent.mcp;

import static org.junit.jupiter.api.Assertions.*;

import io.agentsecurity.core.SecurityBlockedException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Flow;
import org.junit.jupiter.api.Test;

class McpResponseLimitsTest {
    @Test
    void httpCountsAcrossChunksAndCancelsBeforeOversizeDelivery() {
        var state = new McpResponseLimits.State(4);
        var subscriber =
                new LimitedMcpHttpClient.LimitedSubscriber<>(
                        HttpResponse.BodySubscribers.ofByteArray(), state);
        var subscription = new Subscription();
        subscriber.onSubscribe(subscription);
        subscriber.onNext(List.of(ByteBuffer.wrap(new byte[3])));
        subscriber.onNext(List.of(ByteBuffer.wrap(new byte[2])));
        assertTrue(subscription.cancelled);
        var failure =
                assertThrows(
                        CompletionException.class,
                        () -> subscriber.getBody().toCompletableFuture().join());
        assertInstanceOf(SecurityBlockedException.class, failure.getCause());
        assertThrows(SecurityBlockedException.class, state::check);
        subscriber.onComplete();
    }

    @Test
    void exactHttpLimitSucceedsAndEmptyChunksDoNotCount() {
        var subscriber =
                new LimitedMcpHttpClient.LimitedSubscriber<>(
                        HttpResponse.BodySubscribers.ofByteArray(), new McpResponseLimits.State(4));
        subscriber.onSubscribe(new Subscription());
        subscriber.onNext(List.of(ByteBuffer.allocate(0), ByteBuffer.wrap(new byte[4])));
        subscriber.onComplete();
        assertEquals(4, subscriber.getBody().toCompletableFuture().join().length);
    }

    @Test
    void stdioCountsBytesAndResetsAtLineBoundaries() throws Exception {
        byte[] bytes = "abcd\r\nabcd\n".getBytes(StandardCharsets.UTF_8);
        try (var input =
                new McpResponseLimits.LimitedLineInput(
                        new ByteArrayInputStream(bytes), new McpResponseLimits.State(4))) {
            assertArrayEquals(bytes, input.readAllBytes());
        }
    }

    @Test
    void multibyteUnterminatedLineCannotExceedByteBudget() throws Exception {
        var state = new McpResponseLimits.State(4);
        try (var input =
                new McpResponseLimits.LimitedLineInput(
                        new ByteArrayInputStream("中文".getBytes(StandardCharsets.UTF_8)), state)) {
            assertThrows(IOException.class, input::readAllBytes);
            assertThrows(SecurityBlockedException.class, state::check);
        }
    }

    @Test
    void singleByteReadsAreAlsoBounded() throws Exception {
        try (var input =
                new McpResponseLimits.LimitedLineInput(
                        new ByteArrayInputStream(new byte[5]), new McpResponseLimits.State(4))) {
            for (int i = 0; i < 4; i++) {
                assertEquals(0, input.read());
            }
            assertThrows(IOException.class, input::read);
        }
    }

    @Test
    void scopeRestoresAndBindsSharedFailureWithoutAffectingOtherClients() {
        Object transport = new Object();
        Object client = new Object();
        McpResponseLimits.bind(client, transport);
        McpResponseLimits.state(transport).reject();
        assertThrows(SecurityBlockedException.class, () -> McpResponseLimits.check(client));
        McpResponseLimits.check(new Object());
        var original = new ByteArrayInputStream(new byte[0]);
        var previous = McpResponseLimits.enterStdio(new Object());
        try {
            assertNotSame(original, McpResponseLimits.wrapStdio(original));
        } finally {
            McpResponseLimits.exitStdio(previous);
        }
        assertSame(original, McpResponseLimits.wrapStdio(original));
    }

    @Test
    void startupRejectsOutOfRangeLimits() {
        var properties = new Properties();
        properties.setProperty("mcp.max.response.bytes", "0");
        assertThrows(
                IllegalArgumentException.class, () -> McpResponseLimits.initialize(properties));
        McpResponseLimits.initialize(new Properties());
    }

    private static final class Subscription implements Flow.Subscription {
        boolean cancelled;

        @Override
        public void request(long count) {}

        @Override
        public void cancel() {
            cancelled = true;
        }
    }
}
