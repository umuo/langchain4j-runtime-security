package training;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import java.lang.instrument.Instrumentation;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

/** 安装精确匹配的类转换器；教学示例不实现生产故障治理。 */
public final class GuardAgent {
    public static void premain(String agentArgs, Instrumentation instrumentation) {
        System.out.println("[premain] guard installed");
        new AgentBuilder.Default()
                .disableClassFormatChanges()
                .type(named("training.CustomerTool"))
                .transform(
                        (builder, type, loader, module, domain) ->
                                builder.visit(
                                        Advice.to(GuardAdvice.class)
                                                .on(
                                                        named("execute")
                                                                .and(
                                                                        takesArguments(
                                                                                String.class)))))
                .installOn(instrumentation);
    }
}
