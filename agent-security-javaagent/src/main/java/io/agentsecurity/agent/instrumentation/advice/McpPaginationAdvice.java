package io.agentsecurity.agent.instrumentation.advice;

import io.agentsecurity.agent.mcp.McpPagination;
import java.util.function.BiFunction;
import java.util.function.Function;
import net.bytebuddy.asm.Advice;

/** 请求创建前检查页数；页面解析后、加入总列表之前检查累计条目和游标。 */
public final class McpPaginationAdvice {
    @Advice.OnMethodEnter
    public static McpPagination.Budget enter(
            @Advice.Argument(value = 0, readOnly = false) BiFunction<Long, String, Object> requests,
            @Advice.Argument(value = 3, readOnly = false) Function<String, Object> parser) {
        var budget = McpPagination.begin();
        requests = McpPagination.requests(requests, budget);
        parser = McpPagination.pages(parser, budget);
        return budget;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(
            @Advice.Enter McpPagination.Budget budget, @Advice.Thrown Throwable failure) {
        budget.finish(failure == null);
    }
}
