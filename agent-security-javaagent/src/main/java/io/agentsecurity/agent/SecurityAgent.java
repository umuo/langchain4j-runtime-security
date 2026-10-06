package io.agentsecurity.agent;

import io.agentsecurity.agent.instrumentation.AgentInstrumentation;
import java.lang.instrument.Instrumentation;

/** Java Agent 启动入口。只负责串联初始化与插桩注册，禁止提前加载业务 LangChain4j 类。 */
public final class SecurityAgent {

    public static void premain(String arguments, Instrumentation instrumentation) throws Exception {
        // 未指定策略时直接退出，不扫描已加载类、不注册 transformer，也不创建检测和审计线程。
        if (arguments == null || arguments.isBlank()) {
            return;
        }
        AgentBootstrap.initialize(arguments, instrumentation);
        AgentInstrumentation.install(instrumentation);
        io.agentsecurity.core.health.AgentCoverage.global().installed();
    }
}
