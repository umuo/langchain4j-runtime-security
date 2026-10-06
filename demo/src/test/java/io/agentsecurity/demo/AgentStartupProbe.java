package io.agentsecurity.demo;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.util.concurrent.atomic.AtomicInteger;

/** 独立 JVM 探针，用超过旧默认上限的真实模型请求验证打包 Agent 的配置语义。 */
public final class AgentStartupProbe {

    public static void main(String[] arguments) {
        AtomicInteger calls = new AtomicInteger();
        ChatModel model =
                new ChatModel() {
                    @Override
                    public ChatResponse doChat(ChatRequest request) {
                        calls.incrementAndGet();
                        return ChatResponse.builder().aiMessage(AiMessage.from("OK")).build();
                    }
                };
        try {
            model.chat(
                    ChatRequest.builder().messages(UserMessage.from("X".repeat(100001))).build());
            System.out.println("PROBE allowed=true calls=" + calls.get());
        } catch (RuntimeException denied) {
            // 不输出原始输入或异常消息，只报告业务是否实际进入模型。
            System.out.println("PROBE allowed=false calls=" + calls.get());
        }
    }
}
