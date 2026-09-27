package io.agentsecurity.fixture;

import dev.langchain4j.data.message.*;
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.memory.chat.MessageWindowChatMemory;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.service.*;
import dev.langchain4j.store.memory.chat.ChatMemoryStore;
import io.agentsecurity.core.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public final class MemoryFixture {
    public interface Assistant { String chat(@MemoryId String id, @dev.langchain4j.service.UserMessage String text); }
    public interface AsyncAssistant { CompletableFuture<String> chat(@MemoryId String id, @dev.langchain4j.service.UserMessage String text); }
    private static final AtomicInteger reads = new AtomicInteger(), writes = new AtomicInteger(), deletes = new AtomicInteger(), models = new AtomicInteger();
    private static final String ID = "private-memory-session";
    private static final Set<String> ALL = Set.of("memory:read", "memory:write", "memory:delete");
    private static final SecurityContext origin = SecurityContext.authenticated("memory-tenant-a", "memory-user-a", ALL);
    private static final SecurityContext foreign = SecurityContext.authenticated("memory-tenant-b", "memory-user-b", ALL);
    private static final ExecutorService worker = Executors.newSingleThreadExecutor();
    private static final CountDownLatch release = new CountDownLatch(1);
    private static final Queue<Throwable> failures = new ConcurrentLinkedQueue<>();
    private static void identity() {
        if (SecurityContexts.current() != origin) throw new IllegalStateException("Memory context not propagated");
    }
    private static <T> CompletableFuture<T> delayed(T value) {
        var result = new CompletableFuture<T>();
        worker.execute(() -> {
            try {
                if (!release.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Memory timeout");
                try (var scope = SecurityContexts.open(foreign)) {
                    result.complete(value);
                    if (SecurityContexts.current() != foreign) throw new IllegalStateException("Memory worker scope leaked");
                }
                if (SecurityContexts.current() != null) throw new IllegalStateException("Memory worker identity remained");
            } catch (Throwable error) { failures.add(error); result.completeExceptionally(error); }
        });
        return result;
    }
    public static final class Store implements ChatMemoryStore {
        List<ChatMessage> data = new ArrayList<>(List.of(dev.langchain4j.data.message.UserMessage.from("original")));
        @Override public synchronized List<ChatMessage> getMessages(Object id) { identity(); reads.incrementAndGet(); return new ArrayList<>(data); }
        @Override public synchronized void updateMessages(Object id, List<ChatMessage> messages) { identity(); writes.incrementAndGet(); data = new ArrayList<>(messages); }
        @Override public synchronized void deleteMessages(Object id) { identity(); deletes.incrementAndGet(); data.clear(); }
        @Override public CompletableFuture<List<ChatMessage>> getMessagesAsync(Object id) { return delayed(getMessages(id)); }
        @Override public CompletableFuture<Void> updateMessagesAsync(Object id, List<ChatMessage> messages) { updateMessages(id, messages); return delayed(null); }
        @Override public CompletableFuture<Void> deleteMessagesAsync(Object id) { deleteMessages(id); return delayed(null); }
    }
    public static final class Model implements ChatModel {
        @Override public ChatResponse doChat(ChatRequest request) { identity(); models.incrementAndGet(); return ChatResponse.builder().aiMessage(AiMessage.from("answer")).build(); }
        @Override public CompletableFuture<ChatResponse> doChatAsync(ChatRequest request) { return CompletableFuture.completedFuture(doChat(request)); }
    }
    public static void run(String scenario) throws Exception {
        Store store = new Store(); boolean blocked = false;
        if (scenario.endsWith("read-output")) store.data.add(dev.langchain4j.data.message.UserMessage.from("MEMORY_SECRET"));
        if (scenario.equals("memory-size")) store.data = new ArrayList<>(Collections.nCopies(257, dev.langchain4j.data.message.UserMessage.from("safe")));
        ChatMemory memory = MessageWindowChatMemory.builder().id(ID).maxMessages(20).chatMemoryStore(store).build();
        SecurityContext context = origin;
        if (scenario.equals("memory-owner")) context = foreign;
        if (scenario.equals("memory-missing")) context = null;
        if (scenario.startsWith("memory-deny-")) {
            Set<String> permissions = new HashSet<>(ALL); permissions.remove("memory:" + scenario.substring("memory-deny-".length()));
            context = SecurityContext.authenticated(origin.tenantId(), origin.principalId(), permissions);
        }
        CompletableFuture<?> pending = null;
        try {
            try (var scope = SecurityContexts.restore(context)) {
                switch (scenario) {
                    case "memory-ai", "memory-ai-read-output" -> AiServices.builder(Assistant.class).chatModel(new Model())
                            .chatMemoryProvider(id -> memory).build().chat(ID, "question");
                    case "memory-ai-async" -> pending = AiServices.builder(AsyncAssistant.class).chatModel(new Model())
                            .chatMemoryProvider(id -> memory).build().chat(ID, "question");
                    case "memory-read", "memory-read-output", "memory-owner", "memory-missing", "memory-deny-read", "memory-size" -> memory.messages();
                    case "memory-write", "memory-deny-write" -> memory.add(dev.langchain4j.data.message.UserMessage.from("safe"));
                    case "memory-write-input" -> memory.add(dev.langchain4j.data.message.UserMessage.from("MEMORY_SECRET"));
                    case "memory-batch" -> memory.add(dev.langchain4j.data.message.UserMessage.from("safe"), dev.langchain4j.data.message.UserMessage.from("MEMORY_SECRET"));
                    case "memory-set" -> memory.set(List.of(dev.langchain4j.data.message.UserMessage.from("safe"), dev.langchain4j.data.message.UserMessage.from("MEMORY_SECRET")));
                    case "memory-clear", "memory-deny-delete" -> memory.clear();
                    case "memory-store-read-output" -> store.getMessages(ID);
                    case "memory-store-write-input" -> store.updateMessages(ID, List.of(dev.langchain4j.data.message.UserMessage.from("MEMORY_SECRET")));
                    case "memory-store-async-read-output" -> pending = store.getMessagesAsync(ID);
                    case "memory-async-write-input" -> pending = memory.addAsync(List.of(dev.langchain4j.data.message.UserMessage.from("MEMORY_SECRET")));
                    case "memory-async-read" -> pending = memory.messagesAsync();
                    case "memory-async-delete" -> pending = store.deleteMessagesAsync(ID);
                    case "memory-unsupported-id" -> store.getMessages(new Object());
                    default -> throw new IllegalArgumentException("Unknown memory scenario");
                }
            }
            release.countDown(); if (pending != null) pending.get(10, TimeUnit.SECONDS);
        } catch (Exception exception) {
            Throwable error = exception;
            while (error != null && !(error instanceof SecurityBlockedException)) error = error.getCause();
            if (error == null) throw exception;
            blocked = true; System.out.println("BLOCK_REASON=" + ((SecurityBlockedException) error).ruleId());
        } finally { release.countDown(); worker.shutdown(); if (!worker.awaitTermination(10, TimeUnit.SECONDS)) throw new IllegalStateException("Memory shutdown timeout"); }
        if (!failures.isEmpty()) throw new IllegalStateException("Memory worker failure", failures.peek());
        if (SecurityContexts.current() != null) throw new IllegalStateException("Memory request identity leaked");
        System.out.printf("MEMORY_RESULT scenario=%s blocked=%s reads=%d writes=%d deletes=%d modelCalls=%d remaining=%d restored=true%n",
                scenario, blocked, reads.get(), writes.get(), deletes.get(), models.get(), store.data.size());
    }
}
