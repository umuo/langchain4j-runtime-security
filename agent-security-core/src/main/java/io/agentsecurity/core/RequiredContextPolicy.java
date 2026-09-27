package io.agentsecurity.core;

/** Enforce at all protected model/tool phases when the application has integrated authentication scopes. */
public final class RequiredContextPolicy implements Detector {
    @Override public Decision evaluate(SecurityEvent event) {
        return event.context() == null ? Decision.deny("missing-security-context") : Decision.allow();
    }
}
