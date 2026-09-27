package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.bridge.RagBridge;
import io.agentsecurity.core.SecurityContexts;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/** 包装默认 RAG 编排器的组件和执行器，使各异步步骤使用原请求上下文。 */
public final class RagConstructorAdvice {

    @Advice.OnMethodExit
    public static void exit(
            @Advice.FieldValue(
                            value = "queryTransformer",
                            readOnly = false,
                            typing = Assigner.Typing.DYNAMIC)
                    Object transformer,
            @Advice.FieldValue(
                            value = "queryRouter",
                            readOnly = false,
                            typing = Assigner.Typing.DYNAMIC)
                    Object router,
            @Advice.FieldValue(
                            value = "contentAggregator",
                            readOnly = false,
                            typing = Assigner.Typing.DYNAMIC)
                    Object aggregator,
            @Advice.FieldValue(value = "executor", readOnly = false)
                    java.util.concurrent.Executor executor) {
        transformer =
                RagBridge.wrap(
                        transformer,
                        "dev.langchain4j.rag.query.transformer.QueryTransformer",
                        "transform");
        router = RagBridge.wrap(router, "dev.langchain4j.rag.query.router.QueryRouter", "route");
        aggregator =
                RagBridge.wrap(
                        aggregator,
                        "dev.langchain4j.rag.content.aggregator.ContentAggregator",
                        "aggregate");
        executor = SecurityContexts.executor(executor);
    }
}
