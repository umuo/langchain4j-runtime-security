package io.agentsecurity.agent;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Proxy;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 验证无策略时不触碰插桩入口，显式错误配置仍拒绝启动。 */
class SecurityAgentTest {

    @TempDir Path directory;

    @Test
    void unspecifiedPolicyNeverTouchesInstrumentation() throws Exception {
        Instrumentation untouched =
                (Instrumentation)
                        Proxy.newProxyInstance(
                                getClass().getClassLoader(),
                                new Class<?>[] {Instrumentation.class},
                                (proxy, method, arguments) -> {
                                    throw new AssertionError(
                                            "未配置策略时不应调用 Instrumentation: " + method.getName());
                                });
        for (String arguments : new String[] {null, "", " \t\n"}) {
            SecurityAgent.premain(arguments, untouched);
        }
    }

    @Test
    void explicitlyMissingPolicyStillFailsStartup() {
        Instrumentation instrumentation =
                (Instrumentation)
                        Proxy.newProxyInstance(
                                getClass().getClassLoader(),
                                new Class<?>[] {Instrumentation.class},
                                (proxy, method, arguments) -> {
                                    if (method.getName().equals("getAllLoadedClasses")) {
                                        return new Class<?>[0];
                                    }
                                    throw new AssertionError("不应在无效配置时注册插桩");
                                });
        assertThrows(
                NoSuchFileException.class,
                () ->
                        SecurityAgent.premain(
                                directory.resolve("missing.properties").toString(),
                                instrumentation));
    }
}
