package training;

import java.lang.instrument.Instrumentation;

/** 实验一只观察启动顺序，不修改任何业务方法。 */
public final class PrintAgent {
    public static void premain(String agentArgs, Instrumentation instrumentation) {
        System.out.println("[premain] options=" + agentArgs);
    }
}
