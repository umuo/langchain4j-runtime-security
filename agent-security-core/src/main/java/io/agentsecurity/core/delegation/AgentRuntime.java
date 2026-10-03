package io.agentsecurity.core.delegation;

import io.agentsecurity.core.BoundedAuditSink;
import io.agentsecurity.core.Decision;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import io.agentsecurity.core.SecurityEvent;
import io.agentsecurity.core.telemetry.SecurityTelemetry;
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
    private final SecurityTelemetry telemetry;
    private final java.util.concurrent.ScheduledExecutorService expiry;
    private final java.util.EnumMap<AgentEndReason, Long> ended =
            new java.util.EnumMap<>(AgentEndReason.class);
    private boolean closed;
    private boolean auditFailed;

    public AgentRuntime(
            List<AgentDefinition> definitions,
            AgentRuntimeLimits limits,
            BiConsumer<SecurityEvent, Decision> audit) {
        this(definitions, limits, audit, SecurityTelemetry.disabled());
    }

    /** 可与 PolicyEngine 共享收集器，以执行 UUID 关联生命周期及安全决策。 */
    public AgentRuntime(
            List<AgentDefinition> definitions,
            AgentRuntimeLimits limits,
            BiConsumer<SecurityEvent, Decision> audit,
            SecurityTelemetry telemetry) {
        this.telemetry = Objects.requireNonNull(telemetry);
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
        expiry =
                java.util.concurrent.Executors.newSingleThreadScheduledExecutor(
                        task -> {
                            var thread = new Thread(task, "agent-security-expiry");
                            thread.setDaemon(true);
                            thread.setContextClassLoader(AgentRuntime.class.getClassLoader());
                            return thread;
                        });
        expiry.scheduleWithFixedDelay(
                () -> {
                    try {
                        expireNow();
                    } catch (SecurityBlockedException auditError) {
                        /* 已失效所有登记，后续安全操作继续拒绝。 */
                    }
                },
                100,
                100,
                java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    /** 仅供可信认证入口调用；authorizedGrant 必须先经业务授权，方法本身不验证登录凭证。 */
    public synchronized AgentInvocation startRoot(
            String agentId,
            SecurityContext authenticatedUser,
            AgentGrant authorizedGrant,
            Duration lifetime) {
        return startRoot(
                agentId,
                authenticatedUser,
                authorizedGrant,
                lifetime,
                AgentBudgetLimits.defaults());
    }

    /** 预算由可信入口设置，同一根任务的所有后代共享，子任务不能自行增加。 */
    public synchronized AgentInvocation startRoot(
            String agentId,
            SecurityContext authenticatedUser,
            AgentGrant authorizedGrant,
            Duration lifetime,
            AgentBudgetLimits budget) {
        Objects.requireNonNull(budget);
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
        var root =
                new AgentInvocation(
                        this,
                        null,
                        agentId,
                        effective,
                        authenticatedUser,
                        System.nanoTime() + lifetimeNanos(lifetime));
        root.budgetLimits = budget;
        return register(root, SecurityEvent.Phase.AGENT_START);
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
                expireNow();
                throw new SecurityBlockedException("agent-invocation-expired");
            }
            if (active.get(node.invocationId()) != node) {
                throw new SecurityBlockedException("agent-invocation-inactive");
            }
        }
    }

    private AgentInvocation register(AgentInvocation invocation, SecurityEvent.Phase phase) {
        expireNow();
        // 清理可能恰好终止父树，不能在失效父节点下登记孤立的孩子。
        if (invocation.parent != null) {
            requireActive(invocation.parent.context());
        }
        if (active.size() >= limits.maxInvocations()) {
            throw new SecurityBlockedException("agent-capacity");
        }
        var root = root(invocation);
        if (root.budgetInvocations >= root.budgetLimits.maxInvocations()) {
            finish(root, AgentEndReason.BUDGET_EXHAUSTED);
            throw new SecurityBlockedException("agent-budget-invocations");
        }
        root.budgetInvocations++;
        active.put(invocation.invocationId(), invocation);
        try {
            emit(invocation, phase);
            requireActive(invocation.context());
            return invocation;
        } catch (RuntimeException error) {
            if (auditFailed) {
                try {
                    terminate(List.copyOf(active.values()), node -> AgentEndReason.AUDIT_FAILED);
                } catch (RuntimeException cleanupError) {
                    error.addSuppressed(cleanupError);
                }
            }
            throw error;
        }
    }

    private AgentInvocation root(AgentInvocation invocation) {
        var node = invocation;
        while (node.parent != null) {
            node = node.parent;
        }
        return node;
    }

    /** 与登记、失效共用一把锁，保证多个兄弟任务不能同时花掉最后一份额度。 */
    synchronized void consumeProtectedCheck(SecurityContext context) {
        requireActive(context);
        var root = root(context.invocation());
        if (root.budgetChecks >= root.budgetLimits.maxProtectedChecks()) {
            finish(root, AgentEndReason.BUDGET_EXHAUSTED);
            throw new SecurityBlockedException("agent-budget-checks");
        }
        root.budgetChecks++;
    }

    public record BudgetSnapshot(AgentBudgetLimits limits, int invocations, long protectedChecks) {}

    synchronized BudgetSnapshot budgetSnapshot(AgentInvocation invocation) {
        var root = root(invocation);
        return new BudgetSnapshot(root.budgetLimits, root.budgetInvocations, root.budgetChecks);
    }

    /** 成功交付结果和撤销在同一锁内排序，已取消的业务任务不能交付成功结果。 */
    synchronized void complete(AgentInvocation invocation) {
        requireActive(invocation.context());
        finish(invocation, AgentEndReason.COMPLETED);
    }

    private boolean expired(AgentInvocation invocation) {
        for (var node = invocation; node != null; node = node.parent) {
            if (System.nanoTime() - node.deadline >= 0) {
                return true;
            }
        }
        return false;
    }

    /** 活跃委托快照按当前截止时间计算，不依赖遥测队列是否丢记录。 */
    public record Snapshot(int activeInvocations, int maxDepth, Map<AgentEndReason, Long> ended) {}

    public synchronized Snapshot snapshot() {
        var live = active.values().stream().filter(node -> !expired(node)).toList();
        return new Snapshot(
                live.size(),
                live.stream().mapToInt(node -> node.depth).max().orElse(0),
                Map.copyOf(ended));
    }

    /** 可由宿主主动触发；默认后台每 100ms 尝试清理，权限检查始终独立校验实际截止时间。 */
    public synchronized int expireNow() {
        if (closed) {
            return 0;
        }
        var expired = active.values().stream().filter(this::expired).toList();
        terminate(expired, node -> AgentEndReason.EXPIRED);
        return expired.size();
    }

    synchronized void finish(AgentInvocation invocation, AgentEndReason reason) {
        if (active.get(invocation.invocationId()) != invocation) {
            return;
        }
        expireNow();
        if (active.get(invocation.invocationId()) != invocation) {
            return;
        }
        var subtree =
                active.values().stream().filter(node -> descendant(node, invocation)).toList();
        terminate(
                subtree,
                node ->
                        node == invocation
                                ? reason
                                : reason == AgentEndReason.COMPLETED
                                                || reason == AgentEndReason.RELEASED
                                        ? AgentEndReason.PARENT_FINISHED
                                        : AgentEndReason.PARENT_REVOKED);
    }

    /** 先原子失效整批，再逐条审计；审计故障不会让尚未写入日志的后代保留权限。 */
    private void terminate(
            List<AgentInvocation> nodes,
            java.util.function.Function<AgentInvocation, AgentEndReason> reasons) {
        long now = System.nanoTime();
        var ordered =
                nodes.stream()
                        .sorted(java.util.Comparator.comparingInt(node -> node.depth))
                        .toList();
        for (var node : ordered) {
            active.remove(node.invocationId());
            node.end(reasons.apply(node), now);
            ended.merge(node.endReason(), 1L, Long::sum);
        }
        RuntimeException failure = null;
        for (var node : ordered) {
            try {
                var phase =
                        node.endReason() == AgentEndReason.EXPIRED
                                ? SecurityEvent.Phase.AGENT_EXPIRE
                                : node.endReason() == AgentEndReason.COMPLETED
                                                || node.endReason() == AgentEndReason.RELEASED
                                                || node.endReason() == AgentEndReason.FAILED
                                        ? SecurityEvent.Phase.AGENT_FINISH
                                        : SecurityEvent.Phase.AGENT_REVOKE;
                emit(node, phase);
            } catch (RuntimeException error) {
                if (failure == null) {
                    failure = error;
                }
            }
        }
        if (failure != null) {
            if (!active.isEmpty()) {
                try {
                    terminate(List.copyOf(active.values()), node -> AgentEndReason.AUDIT_FAILED);
                } catch (RuntimeException cleanupError) {
                    failure.addSuppressed(cleanupError);
                }
            }
            throw failure;
        }
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
        var event =
                new SecurityEvent(
                        UUID.randomUUID(), phase, invocation.agentId(), "", invocation.context());
        long started = System.nanoTime();
        var outcome = SecurityTelemetry.Outcome.ALLOW;
        try {
            audit.accept(
                    event,
                    invocation.endReason() == null
                            ? Decision.allow()
                            : new Decision(
                                    true,
                                    "agent-end-"
                                            + invocation
                                                    .endReason()
                                                    .name()
                                                    .toLowerCase(java.util.Locale.ROOT)
                                                    .replace('_', '-')));
        } catch (RuntimeException error) {
            outcome = SecurityTelemetry.Outcome.AUDIT_FAILURE;
            auditFailed = true;
            throw new SecurityBlockedException("agent-audit-error");
        } finally {
            telemetry.record(event, outcome, System.nanoTime() - started);
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
        expiry.shutdownNow();
        try {
            terminate(List.copyOf(active.values()), node -> AgentEndReason.RUNTIME_CLOSED);
        } finally {
            active.clear();
            audit.close();
        }
    }
}
