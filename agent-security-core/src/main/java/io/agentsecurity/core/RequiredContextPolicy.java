package io.agentsecurity.core;

/** 要求检测事件具有应用提供的可信身份；缺失身份时拒绝受保护操作。 */
public final class RequiredContextPolicy implements Detector {

    @Override
    public Decision evaluate(SecurityEvent event) {
        return event.context() == null
                ? Decision.deny("missing-security-context")
                : Decision.allow();
    }
}
