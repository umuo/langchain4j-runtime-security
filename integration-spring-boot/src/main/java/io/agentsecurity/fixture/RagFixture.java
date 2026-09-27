package io.agentsecurity.fixture;

import dev.langchain4j.data.document.Metadata;
import dev.langchain4j.data.message.*;
import dev.langchain4j.data.segment.TextSegment;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.rag.*;
import dev.langchain4j.rag.content.Content;
import dev.langchain4j.rag.content.retriever.ContentRetriever;
import dev.langchain4j.rag.query.Query;
import dev.langchain4j.rag.query.router.*;
import dev.langchain4j.rag.query.transformer.QueryTransformer;
import dev.langchain4j.service.AiServices;
import io.agentsecurity.core.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Real AI Services and RAG pipeline; local data only. */
public final class RagFixture {
    public interface Assistant { String chat(String text); }
    public interface AsyncAssistant { CompletableFuture<String> chat(String text); }
    private static final AtomicInteger reads = new AtomicInteger(), models = new AtomicInteger();
    private static final SecurityContext origin = SecurityContext.authenticated("rag-tenant-a", "rag-user-a", Set.of("knowledge:read"));
    private static final SecurityContext foreign = SecurityContext.authenticated("rag-tenant-b", "rag-user-b", Set.of());
    private static final ExecutorService workers = Executors.newFixedThreadPool(2);
    private static final CountDownLatch release = new CountDownLatch(1);
    private static final Queue<Throwable> workerErrors = new ConcurrentLinkedQueue<>();
    private static String scenario;

    private static void identity() {
        SecurityContext context = SecurityContexts.current();
        if (context == null || !context.tenantId().equals(origin.tenantId())) throw new IllegalStateException("RAG context lost");
    }
    private static <T> CompletableFuture<T> delayed(T value) {
        identity();
        var result = new CompletableFuture<T>();
        workers.execute(() -> {
            try {
                if (!release.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("release timeout");
                try (var scope = SecurityContexts.open(foreign)) {
                    result.complete(value);
                    if (SecurityContexts.current() != foreign) throw new IllegalStateException("worker context leaked");
                }
                if (SecurityContexts.current() != null) throw new IllegalStateException("worker context remained");
            } catch (Throwable error) { workerErrors.add(error); result.completeExceptionally(error); }
        });
        return result;
    }
    private static List<Content> data() {
        identity(); reads.incrementAndGet();
        if (scenario.equals("rag-size")) return Collections.nCopies(257, Content.from("short"));
        if (scenario.equals("rag-metadata")) return List.of(Content.from(TextSegment.from("safe", Metadata.from("source", "RAG_SECRET"))));
        return List.of(Content.from(scenario.endsWith("output") ? "RAG_SECRET" : "safe knowledge"));
    }
    public static class Retriever implements ContentRetriever {
        @Override public List<Content> retrieve(Query query) { return data(); }
        @Override public CompletableFuture<List<Content>> retrieveAsync(Query query) {
            if (scenario.equals("rag-null-future")) { reads.incrementAndGet(); return null; }
            return delayed(data());
        }
    }
    public static class BlockingRetriever implements ContentRetriever {
        @Override public List<Content> retrieve(Query query) { return data(); }
    }
    public static class Model implements ChatModel {
        @Override public ChatResponse doChat(ChatRequest request) {
            identity(); models.incrementAndGet(); return ChatResponse.builder().aiMessage(AiMessage.from("done")).build();
        }
        @Override public CompletableFuture<ChatResponse> doChatAsync(ChatRequest request) { return CompletableFuture.completedFuture(doChat(request)); }
    }
    public static class Transformer implements QueryTransformer {
        @Override public Collection<Query> transform(Query query) { identity(); return List.of(query); }
        @Override public CompletableFuture<Collection<Query>> transformAsync(Query query) { return delayed(List.of(query)); }
    }
    public static class Router implements QueryRouter {
        @Override public Collection<ContentRetriever> route(Query query) { identity(); return List.of(new Retriever()); }
        @Override public CompletableFuture<Collection<ContentRetriever>> routeAsync(Query query) { return delayed(List.of(new Retriever())); }
    }

    public static void run(String selected) throws Exception {
        scenario = selected; boolean blocked = false;
        ExecutorService custom = Executors.newFixedThreadPool(2);
        try {
            SecurityContext context = scenario.equals("rag-missing") ? null : scenario.equals("rag-permission")
                    ? SecurityContext.authenticated(origin.tenantId(), origin.principalId(), Set.of()) : origin;
            CompletableFuture<?> pending = null;
            try (var scope = SecurityContexts.restore(context)) {
                if (scenario.startsWith("rag-direct")) {
                    var retriever = new Retriever();
                    if (scenario.equals("rag-direct-async")) pending = retriever.retrieveAsync(Query.from("lookup"));
                    else retriever.retrieve(Query.from("lookup"));
                } else if (scenario.equals("rag-custom-augmentor-output")) {
                    RetrievalAugmentor augmentor = request -> new AugmentationResult(UserMessage.from("RAG_SECRET"), List.of());
                    AiServices.builder(Assistant.class).chatModel(new Model()).retrievalAugmentor(augmentor).build().chat("lookup");
                } else {
                    var builder = DefaultRetrievalAugmentor.builder().contentRetriever(new Retriever());
                    if (scenario.equals("rag-lambda-output")) builder.contentRetriever(query -> data());
                    if (scenario.equals("rag-transformed-input")) builder.queryTransformer(query -> List.of(Query.from("RAG_SECRET")));
                    if (scenario.equals("rag-parallel") || scenario.equals("rag-custom-executor")) {
                        // A lambda router verifies the constructor dispatch seam too.
                        builder.queryRouter(query -> List.of(new Retriever(), (ContentRetriever) q -> data()));
                        if (scenario.equals("rag-custom-executor")) builder.executor(custom);
                    }
                    boolean async = scenario.equals("rag-async") || scenario.equals("rag-async-output")
                            || scenario.equals("rag-offload") || scenario.equals("rag-null-future");
                    if (scenario.equals("rag-async") || scenario.equals("rag-async-output"))
                        builder.queryTransformer(new Transformer()).queryRouter(new Router());
                    if (scenario.equals("rag-offload")) builder.contentRetriever(new BlockingRetriever()).offloadBlocking(true);
                    if (async) pending = AiServices.builder(AsyncAssistant.class).chatModel(new Model())
                            .retrievalAugmentor(builder.build()).build().chat("lookup");
                    else AiServices.builder(Assistant.class).chatModel(new Model()).retrievalAugmentor(builder.build()).build()
                            .chat(scenario.equals("rag-input") ? "RAG_SECRET" : "lookup");
                }
            }
            release.countDown();
            if (pending != null) pending.get(10, TimeUnit.SECONDS);
        } catch (Exception exception) {
            Throwable error = exception;
            while (error != null && !(error instanceof SecurityBlockedException)) error = error.getCause();
            if (error == null) throw exception;
            blocked = true; System.out.println("BLOCK_REASON=" + ((SecurityBlockedException) error).ruleId());
        } finally {
            release.countDown(); workers.shutdown(); custom.shutdown();
            if (!workers.awaitTermination(10, TimeUnit.SECONDS) || !custom.awaitTermination(10, TimeUnit.SECONDS))
                throw new IllegalStateException("RAG worker shutdown timeout");
        }
        if (!workerErrors.isEmpty()) throw new IllegalStateException("Worker identity test failed", workerErrors.peek());
        if (SecurityContexts.current() != null) throw new IllegalStateException("request context leaked");
        System.out.printf("RAG_RESULT scenario=%s blocked=%s reads=%d modelCalls=%d restored=true%n", scenario, blocked, reads.get(), models.get());
    }
}
