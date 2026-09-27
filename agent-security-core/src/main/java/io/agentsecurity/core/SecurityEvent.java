package io.agentsecurity.core;

/** 单次检测的不可变事件。正文和资源标识只供内存检测使用，内置审计不得序列化这些字段。 */
public record SecurityEvent(
        java.util.UUID id,
        Phase phase,
        String operation,
        String text,
        SecurityContext context,
        ResourceRef resource) {

    public SecurityEvent {
        java.util.Objects.requireNonNull(id);
        java.util.Objects.requireNonNull(phase);
        java.util.Objects.requireNonNull(operation);
    }

    public SecurityEvent(Phase phase, String operation, String text) {
        this(java.util.UUID.randomUUID(), phase, operation, text, SecurityContexts.current());
    }

    public SecurityEvent(
            java.util.UUID id,
            Phase phase,
            String operation,
            String text,
            SecurityContext context) {
        this(id, phase, operation, text, context, null);
    }

    public SecurityEvent(java.util.UUID id, Phase phase, String operation, String text) {
        this(id, phase, operation, text, SecurityContexts.current());
    }

    @Override
    public String toString() {
        return "SecurityEvent[id=" + id + ", phase=" + phase + "]";
    }

    public enum Phase {
        AGENT_START,
        AGENT_DELEGATE,
        AGENT_FINISH,
        AGENT_REVOKE,
        AGENT_EXPIRE,
        MODEL_INPUT,
        MODEL_OUTPUT,
        TOOL_INPUT,
        TOOL_OUTPUT,
        RETRIEVAL_INPUT,
        RETRIEVAL_OUTPUT,
        AUGMENTATION_INPUT,
        AUGMENTATION_OUTPUT,
        MEMORY_READ_INPUT,
        MEMORY_READ_OUTPUT,
        MEMORY_WRITE,
        MEMORY_DELETE
    }
}
