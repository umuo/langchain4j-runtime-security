package io.agentsecurity.core;

/** Payload is in-memory only; audit sinks must not serialize it. */
public record SecurityEvent(java.util.UUID id, Phase phase, String operation, String text, SecurityContext context, ResourceRef resource) {
    public SecurityEvent {
        java.util.Objects.requireNonNull(id);
        java.util.Objects.requireNonNull(phase);
        java.util.Objects.requireNonNull(operation);
    }
    public SecurityEvent(Phase phase, String operation, String text) {
        this(java.util.UUID.randomUUID(), phase, operation, text, SecurityContexts.current());
    }
    public SecurityEvent(java.util.UUID id, Phase phase, String operation, String text, SecurityContext context) {
        this(id, phase, operation, text, context, null);
    }
    public SecurityEvent(java.util.UUID id, Phase phase, String operation, String text) {
        this(id, phase, operation, text, SecurityContexts.current());
    }
    @Override public String toString() { return "SecurityEvent[id=" + id + ", phase=" + phase + "]"; }
    public enum Phase { MODEL_INPUT, MODEL_OUTPUT, TOOL_INPUT, TOOL_OUTPUT,
        RETRIEVAL_INPUT, RETRIEVAL_OUTPUT, AUGMENTATION_INPUT, AUGMENTATION_OUTPUT,
        MEMORY_READ_INPUT, MEMORY_READ_OUTPUT, MEMORY_WRITE, MEMORY_DELETE }
}
