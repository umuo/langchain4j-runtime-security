package training;

/** 通过实际业务计数，区分正常执行与执行前阻断。 */
public final class Demo {
    public static void main(String[] args) {
        System.out.println("[main] started");
        String operation = args.length == 0 ? "readCustomer" : args[0];
        try {
            String result = new CustomerTool().execute(operation);
            System.out.println("[main] result=" + result);
        } catch (IllegalStateException denied) {
            System.out.println("[main] blocked=" + denied.getMessage());
        }
        System.out.println("[main] calls=" + CustomerTool.calls);
    }
}
