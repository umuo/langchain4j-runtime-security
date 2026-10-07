package training;

/** 普通业务类：不依赖 Agent、Byte Buddy 或安全 SDK。 */
public final class CustomerTool {
    public static int calls;

    public String execute(String operation) {
        calls++;
        System.out.println("[business] execute=" + operation);
        return "done:" + operation;
    }
}
