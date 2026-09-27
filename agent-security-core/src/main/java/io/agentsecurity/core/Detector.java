package io.agentsecurity.core;

/** Implementations must be thread-safe. A null result or exception fails closed. */
@FunctionalInterface
public interface Detector {
    Decision evaluate(SecurityEvent event);
}
