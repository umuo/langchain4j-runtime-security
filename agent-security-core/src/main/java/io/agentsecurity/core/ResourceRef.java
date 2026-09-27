package io.agentsecurity.core;

/** A requested resource, not proof of ownership. Never emit its identifier in built-in logs. */
public record ResourceRef(String type, String id) {
    public ResourceRef {
        if (type == null || !type.matches("[a-z:-]{1,40}") || id == null || id.length() > 1024)
            throw new IllegalArgumentException("Invalid resource reference");
    }
    @Override public String toString() { return "ResourceRef[type=" + type + "]"; }
}
