package training;

import net.bytebuddy.asm.Advice;

/** 实验二的检查逻辑：执行前拒绝危险操作，成功返回后观察结果。 */
public final class GuardAdvice {
    @Advice.OnMethodEnter
    public static void enter(@Advice.Argument(0) String operation) {
        System.out.println("[advice] before=" + operation);
        if ("deleteAll".equals(operation)) {
            throw new IllegalStateException("demo-deny-tool");
        }
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Return String result) {
        System.out.println("[advice] after=" + result);
    }
}
