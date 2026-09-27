package io.agentsecurity.fixture;

import io.agentsecurity.core.*;

/** Tests discovery of an application's SPI from BOOT-INF/classes. No network access. */
public final class FixtureDetector implements Detector {
    @Override public Decision evaluate(SecurityEvent event) {
        // Fixture ACL represents a trusted resource-owner lookup, independent of the requested memory ID.
        if (event.resource() != null && event.resource().equals(new ResourceRef("memory:string", "private-memory-session"))
                && (event.context() == null || !event.context().tenantId().equals("memory-tenant-a")))
            return Decision.deny("memory-owner-denied");
        if (event.phase() == SecurityEvent.Phase.RETRIEVAL_INPUT && event.context() != null
                && !event.context().permissions().contains("knowledge:read")) return Decision.deny("rag-permission-denied");
        if (event.text().contains("PLUGIN_SLEEP")) {
            try { Thread.sleep(10_000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        if (event.text().contains("PLUGIN_FAILURE")) throw new IllegalStateException("sensitive detector detail");
        return event.text().contains("PLUGIN_DENY") ? Decision.deny("boot-plugin") : Decision.allow();
    }
}
