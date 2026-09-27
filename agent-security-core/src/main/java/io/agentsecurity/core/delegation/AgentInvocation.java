package io.agentsecurity.core.delegation;

import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/** 调度器签发的单次执行句柄。构造器不对外开放；结束后旧上下文不再具有有效委托。 */
public final class AgentInvocation implements AutoCloseable {
    final AgentRuntime runtime;
    final AgentInvocation parent;
    final long deadline;
    final int depth;
    private final UUID invocationId = UUID.randomUUID();
    private final UUID delegationId = UUID.randomUUID();
    private final String agentId;
    private final AgentGrant grant;
    private final SecurityContext context;
    private final AtomicBoolean started = new AtomicBoolean();

    AgentInvocation(
            AgentRuntime runtime,
            AgentInvocation parent,
            String agentId,
            AgentGrant grant,
            SecurityContext identity,
            long deadline) {
        this.runtime = runtime;
        this.parent = parent;
        this.agentId = agentId;
        this.grant = grant;
        this.deadline = deadline;
        this.depth = parent == null ? 0 : parent.depth + 1;
        this.context =
                new SecurityContext(
                        parent == null ? UUID.randomUUID() : identity.runId(),
                        identity.tenantId(),
                        identity.principalId(),
                        grant.permissions(),
                        this);
    }

    public UUID invocationId() {
        return invocationId;
    }

    public UUID delegationId() {
        return delegationId;
    }

    public UUID parentInvocationId() {
        return parent == null ? null : parent.invocationId();
    }

    public UUID rootRunId() {
        return context.runId();
    }

    public String agentId() {
        return agentId;
    }

    public AgentGrant grant() {
        return grant;
    }

    public SecurityContext context() {
        return context;
    }

    /** 同步执行一次并释放登记；父任务应等待子任务完成后再返回。 */
    public <T> T call(Callable<T> task) throws Exception {
        java.util.Objects.requireNonNull(task);
        start();
        return execute(task);
    }

    /** 提交时绑定子身份；排队期间撤销或过期时，不进入任务体。取消不保证中断外部 I/O。 */
    public <T> CompletableFuture<T> submit(Executor executor, Callable<T> task) {
        java.util.Objects.requireNonNull(executor);
        java.util.Objects.requireNonNull(task);
        start();
        var result = new CompletableFuture<T>();
        result.whenComplete(
                (value, error) -> {
                    if (result.isCancelled()) {
                        revoke();
                    }
                });
        try {
            executor.execute(
                    () -> {
                        try {
                            result.complete(execute(task));
                        } catch (Throwable error) {
                            result.completeExceptionally(error);
                        }
                    });
        } catch (RuntimeException error) {
            try {
                revoke();
            } catch (RuntimeException auditError) {
                error.addSuppressed(auditError);
            }
            result.completeExceptionally(error);
        }
        return result;
    }

    private void start() {
        runtime.requireActive(context);
        if (!started.compareAndSet(false, true)) {
            throw new SecurityBlockedException("agent-invocation-reused");
        }
    }

    private <T> T execute(Callable<T> task) throws Exception {
        try {
            runtime.requireActive(context);
            try (var scope = SecurityContexts.open(context)) {
                return task.call();
            }
        } finally {
            close();
        }
    }

    /** 使本次执行及所有后代的后续检查失败，不回滚已经发生的业务副作用。 */
    public void revoke() {
        runtime.finish(this, true);
    }

    @Override
    public void close() {
        runtime.finish(this, false);
    }

    @Override
    public String toString() {
        return "AgentInvocation[id=" + invocationId + "]";
    }
}
