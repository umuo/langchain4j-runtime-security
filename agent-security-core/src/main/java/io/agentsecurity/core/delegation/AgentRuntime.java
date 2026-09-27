package io.agentsecurity.core.delegation;

import io.agentsecurity.core.BoundedAuditSink;
import io.agentsecurity.core.Decision;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import io.agentsecurity.core.SecurityEvent;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.BiConsumer;

/** 同 JVM 的可信调度器。维护有界执行登记，签发收窄后的身份；不是恶意代码隔离沙箱。 */
public final class AgentRuntime implements AutoCloseable {
    private final Map<String, AgentDefinition> definitions;
    private final Map<UUID, AgentInvocation> active = new HashMap<>();
    private final AgentRuntimeLimits limits;
    private final BoundedAuditSink audit;
    private boolean closed;
    private boolean auditFailed;

    public AgentRuntime(
            List<AgentDefinition> definitions,
            AgentRuntimeLimits limits,
            BiConsumer<SecurityEvent, Decision> audit) {
        this.limits = Objects.requireNonNull(limits);
        var registry = new HashMap<String, AgentDefinition>();
        if (definitions.isEmpty() || definitions.size() > 512) {
            throw new IllegalArgumentException("Invalid agent definitions");
        }
        for (var definition : definitions) {
            if (registry.putIfAbsent(definition.agentId(), definition) != null) {
                throw new IllegalArgumentException("Duplicate agent definition");
            }
        }
        for (var definition : definitions) {
            if (!registry.keySet().containsAll(definition.allowedChildren())) {
                throw new IllegalArgumentException("Unknown child definition");
            }
        }
        this.definitions = Map.copyOf(registry);
        this.audit = new BoundedAuditSink(audit, Duration.ofSeconds(1), 128);
    }

    /** 仅供可信认证入口调用；authorizedGrant 必须先经业务授权，方法本身不验证登录凭证。 */
    public synchronized AgentInvocation startRoot(
            String agentId,
            SecurityContext authenticatedUser,
            AgentGrant authorizedGrant,
            Duration lifetime) {
        Objects.requireNonNull(authenticatedUser);
        var current = SecurityContexts.current();
        if (authenticatedUser.invocation() != null
                || (current != null && current.invocation() != null)) {
            throw new SecurityBlockedException("agent-root-from-child");
        }
        ensureOpen();
        var definition = definition(agentId);
        var effective = authorizedGrant.intersect(definition.maximumGrant());
        var permissions = new java.util.HashSet<>(effective.permissions());
        permissions.retainAll(authenticatedUser.permissions());
        effective =
                new AgentGrant(
                        permissions,
                        effective.tools(),
                        effective.retrievers(),
                        effective.memoryResources());
        return register(
                new AgentInvocation(
                        this,
                        null,
                        agentId,
                        effective,
                        authenticatedUser,
                        System.nanoTime() + lifetimeNanos(lifetime)),
                SecurityEvent.Phase.AGENT_START);
    }

    /** 必须在有效父执行作用域中申请子任务，父身份不能由请求参数指定。 */
    public synchronized AgentInvocation delegate(
            String agentId, AgentGrant requested, Duration lifetime) {
        var parentContext = SecurityContexts.current();
        if (parentContext == null || parentContext.invocation() == null) {
            throw new SecurityBlockedException("agent-parent-required");
        }
        requireActive(parentContext);
        var parent = parentContext.invocation();
        if (!definition(parent.agentId()).allowedChildren().contains(agentId)) {
            throw new SecurityBlockedException("agent-child-denied");
        }
        if (parent.depth >= limits.maxDepth()) {
            throw new SecurityBlockedException("agent-depth-limit");
        }
        var effective =
                requested.intersect(parent.grant()).intersect(definition(agentId).maximumGrant());
        long now = System.nanoTime();
        long remaining = parent.deadline - now;
        long deadline = now + Math.min(lifetimeNanos(lifetime), Math.max(0, remaining));
        return register(
                new AgentInvocation(this, parent, agentId, effective, parentContext, deadline),
                SecurityEvent.Phase.AGENT_DELEGATE);
    }

    synchronized void requireActive(SecurityContext context) {
        ensureOpen();
        var invocation = context.invocation();
        if (invocation == null
                || invocation.runtime != this
                || !invocation.context().equals(context)) {
            throw new SecurityBlockedException("agent-context-mismatch");
        }
        for (var node = invocation; node != null; node = node.parent) {
            if (System.nanoTime() - node.deadline >= 0) {
                throw new SecurityBlockedException("agent-invocation-expired");
            }
            if (active.get(node.invocationId()) != node) {
                throw new SecurityBlockedException("agent-invocation-inactive");
            }
        }
    }

    private AgentInvocation register(AgentInvocation invocation, SecurityEvent.Phase phase) {
        // 没有定时清扫线程；新建时回收过期树，检查时也逐级验证截止时间。
        active.values().removeIf(node -> expired(node));
        if (active.size() >= limits.maxInvocations()) {
            throw new SecurityBlockedException("agent-capacity");
        }
        active.put(invocation.invocationId(), invocation);
        try {
            emit(invocation, phase);
            requireActive(invocation.context());
            return invocation;
        } catch (RuntimeException error) {
            active.remove(invocation.invocationId());
            throw error;
        }
    }

    private boolean expired(AgentInvocation invocation) {
        for (var node = invocation; node != null; node = node.parent) {
            if (System.nanoTime() - node.deadline >= 0) {
                return true;
            }
        }
        return false;
    }

    synchronized void finish(AgentInvocation invocation, boolean revoked) {
        if (active.get(invocation.invocationId()) != invocation) {
            return;
        }
        // 先失效整棵子树，即使后续审计失败也不能恢复委托。
        active.values().removeIf(node -> descendant(node, invocation));
        emit(
                invocation,
                revoked ? SecurityEvent.Phase.AGENT_REVOKE : SecurityEvent.Phase.AGENT_FINISH);
    }

    private boolean descendant(AgentInvocation node, AgentInvocation ancestor) {
        for (var current = node; current != null; current = current.parent) {
            if (current == ancestor) {
                return true;
            }
        }
        return false;
    }

    private void emit(AgentInvocation invocation, SecurityEvent.Phase phase) {
        try {
            audit.accept(
                    new SecurityEvent(
                            UUID.randomUUID(),
                            phase,
                            invocation.agentId(),
                            "",
                            invocation.context()),
                    Decision.allow());
        } catch (RuntimeException error) {
            auditFailed = true;
            throw new SecurityBlockedException("agent-audit-error");
        }
    }

    private void ensureOpen() {
        if (closed || auditFailed) {
            throw new SecurityBlockedException(
                    closed ? "agent-runtime-closed" : "agent-audit-error");
        }
    }

    private AgentDefinition definition(String id) {
        var definition = definitions.get(id);
        if (definition == null) {
            throw new SecurityBlockedException("agent-unknown");
        }
        return definition;
    }

    private long lifetimeNanos(Duration lifetime) {
        if (lifetime == null
                || lifetime.isZero()
                || lifetime.isNegative()
                || lifetime.compareTo(limits.maxLifetime()) > 0) {
            throw new IllegalArgumentException("Invalid invocation lifetime");
        }
        return lifetime.toNanos();
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            for (var invocation : List.copyOf(active.values())) {
                if (invocation.parent == null) {
                    finish(invocation, true);
                }
            }
        } finally {
            active.clear();
            audit.close();
        }
    }
}
