package io.agentsecurity.core.delegation;

import io.agentsecurity.core.ResourceRef;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/** 不可变能力范围；所有集合均为精确允许列表，空集合不表示无限权限。 */
public record AgentGrant(
        Set<String> permissions,
        Set<String> tools,
        Set<String> retrievers,
        Set<ResourceRef> memoryResources) {
    public AgentGrant {
        permissions = names(permissions, 128);
        if (permissions.size() > 128
                || permissions.stream().anyMatch(p -> !p.matches("[a-zA-Z0-9@._:-]{1,128}"))) {
            throw new IllegalArgumentException("Invalid delegated permissions");
        }
        tools = names(tools, 256);
        retrievers = names(retrievers, 512);
        memoryResources = Set.copyOf(memoryResources);
        if (memoryResources.size() > 512) {
            throw new IllegalArgumentException("Too many memory resources");
        }
    }

    public static AgentGrant tools(Set<String> permissions, Set<String> tools) {
        return new AgentGrant(permissions, tools, Set.of(), Set.of());
    }

    public AgentGrant intersect(AgentGrant other) {
        Objects.requireNonNull(other);
        return new AgentGrant(
                intersection(permissions, other.permissions),
                intersection(tools, other.tools),
                intersection(retrievers, other.retrievers),
                intersection(memoryResources, other.memoryResources));
    }

    static Set<String> names(Set<String> values, int maxLength) {
        var copy = Set.copyOf(values);
        if (copy.size() > 512
                || copy.stream().anyMatch(v -> v.isBlank() || v.length() > maxLength)) {
            throw new IllegalArgumentException("Invalid capability names");
        }
        return copy;
    }

    private static <T> Set<T> intersection(Set<T> left, Set<T> right) {
        var result = new HashSet<>(left);
        result.retainAll(right);
        return Set.copyOf(result);
    }

    @Override
    public String toString() {
        return "AgentGrant[permissions=" + permissions.size() + ", tools=" + tools.size() + "]";
    }
}
