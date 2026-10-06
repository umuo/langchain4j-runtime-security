package io.agentsecurity.agent;

/** 在独立 JVM 中复用启动校验；只返回通过／失败，不输出配置值或私密内容。 */
public final class PolicyCheck {

    private PolicyCheck() {}

    public static void main(String[] arguments) {
        if (arguments.length != 1 || arguments[0].isBlank()) {
            System.err.println(
                    "用法：java -cp agent-security-javaagent.jar io.agentsecurity.agent.PolicyCheck /path/policy.properties");
            System.exit(2);
            return;
        }
        try {
            AgentBootstrap.validateConfiguration(arguments[0]);
            System.out.println("配置校验通过；未安装插桩、未调用检测服务、未写入审计文件。");
        } catch (Exception failure) {
            // 数值解析异常可能携带配置值，不将异常消息或堆栈输出到部署日志。
            System.err.println(
                    "配置校验失败（" + failure.getClass().getSimpleName() + "）；请检查重复键、取值、路径和工具 JSON。");
            System.exit(1);
        }
    }
}
