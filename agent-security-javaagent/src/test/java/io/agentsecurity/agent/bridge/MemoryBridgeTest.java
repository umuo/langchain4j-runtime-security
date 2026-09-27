package io.agentsecurity.agent.bridge;

import static org.junit.jupiter.api.Assertions.*;

import dev.langchain4j.data.message.*;
import dev.langchain4j.memory.ChatMemory;
import io.agentsecurity.core.LocalPolicy;
import io.agentsecurity.core.PolicyEngine;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import io.agentsecurity.core.SecurityEvent;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;

class MemoryBridgeTest {

    PolicyEngine engine;

    final List<SecurityEvent> events = new CopyOnWriteArrayList<>();

    @BeforeEach
    void setup() {
        Properties properties = new Properties();
        properties.setProperty("deny.text", "SECRET_MEMORY");
        engine =
                new PolicyEngine(
                        List.of(new LocalPolicy(properties)),
                        (event, decision) -> events.add(event));
        Bridge.initialize(engine, 1000);
        MemoryBridge.initialize(new Properties());
    }

    @AfterEach
    void close() {
        engine.close();
    }

    public static class Memory implements ChatMemory {

        final List<ChatMessage> stored = new ArrayList<>(List.of(UserMessage.from("original")));

        final AtomicInteger mutations = new AtomicInteger();

        @Override
        public Object id() {
            return "private-memory-id";
        }

        @Override
        public void add(ChatMessage message) {
            mutations.incrementAndGet();
            stored.add(message);
        }

        @Override
        public List<ChatMessage> messages() {
            return stored;
        }

        @Override
        public void clear() {
            mutations.incrementAndGet();
            stored.clear();
        }
    }

    @Test
    void batchValidationPrecedesEveryDefaultAddOrSetSideEffect() {
        Memory target = new Memory();
        var guarded = (ChatMemory) MemoryBridge.wrap(target, MemoryBridge.MEMORY);
        assertThrows(
                SecurityBlockedException.class,
                () -> guarded.add(UserMessage.from("safe"), UserMessage.from("SECRET_MEMORY")));
        assertThrows(
                SecurityBlockedException.class,
                () ->
                        guarded.set(
                                List.of(
                                        UserMessage.from("safe"),
                                        UserMessage.from("SECRET_MEMORY"))));
        assertEquals(0, target.mutations.get());
        assertEquals(List.of(UserMessage.from("original")), target.stored);
    }

    @Test
    void oneShotIterableIsConsumedOnceAndReplacedBeforeDelegateRuns() {
        var target = new Memory();
        var guarded = (ChatMemory) MemoryBridge.wrap(target, MemoryBridge.MEMORY);
        AtomicInteger iterators = new AtomicInteger();
        Iterable<ChatMessage> once =
                () -> {
                    if (iterators.incrementAndGet() != 1) {
                        throw new IllegalStateException("one shot");
                    }
                    return List.<ChatMessage>of(UserMessage.from("safe"), AiMessage.from("answer"))
                            .iterator();
                };
        guarded.set(once);
        assertEquals(1, iterators.get());
        assertEquals(2, target.stored.size());
    }

    @Test
    void unboundedIterableFailsAtConfiguredLimitWithoutMutation() {
        Properties p = new Properties();
        p.setProperty("memory.max.messages", "2");
        MemoryBridge.initialize(p);
        var target = new Memory();
        var guarded = (ChatMemory) MemoryBridge.wrap(target, MemoryBridge.MEMORY);
        Iterable<ChatMessage> infinite =
                () ->
                        new Iterator<>() {

                            public boolean hasNext() {
                                return true;
                            }

                            public ChatMessage next() {
                                return UserMessage.from("safe");
                            }
                        };
        assertEquals(
                "memory-message-limit",
                assertThrows(SecurityBlockedException.class, () -> guarded.add(infinite)).ruleId());
        assertEquals(0, target.mutations.get());
    }

    @Test
    void readIsValidatedAndReturnsIndependentMutableList() {
        var target = new Memory();
        var guarded = (ChatMemory) MemoryBridge.wrap(target, MemoryBridge.MEMORY);
        var list = guarded.messages();
        list.add(AiMessage.from("changed"));
        assertEquals(1, target.stored.size());
        target.stored.add(UserMessage.from("SECRET_MEMORY"));
        assertThrows(SecurityBlockedException.class, guarded::messages);
    }

    @Test
    void resourceIdentifiersAreTypedBoundedAndNotInToString() {
        assertNotEquals(MemoryBridge.resource("42"), MemoryBridge.resource(42));
        assertNotEquals(MemoryBridge.resource(42L), MemoryBridge.resource(42));
        assertEquals(
                "unsupported-memory-id",
                assertThrows(
                                SecurityBlockedException.class,
                                () -> MemoryBridge.resource(new Object()))
                        .ruleId());
        assertEquals(
                "memory-id-limit",
                assertThrows(
                                SecurityBlockedException.class,
                                () -> MemoryBridge.resource("x".repeat(1025)))
                        .ruleId());
        assertFalse(
                MemoryBridge.resource("private-memory-id")
                        .toString()
                        .contains("private-memory-id"));
    }

    @Test
    void permissionsApplyBeforeEachOperationAndMissingIdentityIsRejected() {
        Properties p = new Properties();
        p.setProperty("memory.read.permission", "memory:read");
        p.setProperty("memory.write.permission", "memory:write");
        p.setProperty("memory.delete.permission", "memory:delete");
        var policy = new LocalPolicy(p);
        for (var phase :
                List.of(
                        SecurityEvent.Phase.MEMORY_READ_INPUT,
                        SecurityEvent.Phase.MEMORY_WRITE,
                        SecurityEvent.Phase.MEMORY_DELETE)) {
            assertEquals(
                    "missing-security-context",
                    policy.evaluate(new SecurityEvent(phase, "memory", "")).ruleId());
            try (var scope =
                    SecurityContexts.open(SecurityContext.authenticated("t", "p", Set.of()))) {
                assertEquals(
                        "permission-denied",
                        policy.evaluate(new SecurityEvent(phase, "memory", "")).ruleId());
            }
        }
        p.setProperty("memory.read.permission", "");
        assertThrows(IllegalArgumentException.class, () -> new LocalPolicy(p));
    }

    @Test
    void voidFutureSuccessIsAllowedReadNullRejectedAndCancellationPropagates() {
        var memory = new Memory();
        var write =
                MemoryBridge.before(
                        memory, "addAsync", new Object[] {List.of(UserMessage.from("safe"))});
        assertNull(MemoryBridge.guardFuture(write, CompletableFuture.completedFuture(null)).join());
        var read = MemoryBridge.before(memory, "messagesAsync", new Object[0]);
        var result = MemoryBridge.guardFuture(read, CompletableFuture.completedFuture(null));
        assertInstanceOf(
                SecurityBlockedException.class,
                assertThrows(CompletionException.class, result::join).getCause());
        var source = new CompletableFuture<>();
        MemoryBridge.guardFuture(read, source).cancel(true);
        assertTrue(source.isCancelled());
    }

    @Test
    void futureReadAndEventKeepOriginalContextAndResource() {
        SecurityContext origin = SecurityContext.authenticated("t-a", "u-a", Set.of());
        SecurityContext foreign = SecurityContext.authenticated("t-b", "u-b", Set.of());
        MemoryBridge.Call call;
        try (var scope = SecurityContexts.open(origin)) {
            call = MemoryBridge.before(new Memory(), "messagesAsync", new Object[0]);
        }
        var source = new CompletableFuture<List<ChatMessage>>();
        var result = MemoryBridge.guardFuture(call, source);
        try (var scope = SecurityContexts.open(foreign)) {
            source.complete(List.of(UserMessage.from("safe")));
            assertSame(foreign, SecurityContexts.current());
        }
        result.join();
        var event = events.get(events.size() - 1);
        assertSame(origin, event.context());
        assertEquals("private-memory-id", event.resource().id());
        assertFalse(event.toString().contains("private-memory-id"));
    }

    @Test
    void nullMessagesAndInvalidLimitAreRejected() {
        assertThrows(
                SecurityBlockedException.class,
                () -> MemoryBridge.before(new Memory(), "add", new Object[] {null}));
        Properties p = new Properties();
        p.setProperty("memory.max.messages", "4097");
        assertThrows(IllegalArgumentException.class, () -> MemoryBridge.initialize(p));
    }
}
