# 多 Agent 共享预算与协作式取消

这项能力位于 `agent-security-core`，不依赖 Spring。可信入口为每次根任务设置累计预算，同一树的父、子、孙任务共享额度；任务结束不返还。超额申请会先使整棵树失效，再写生命周期审计，后续安全检查和成功结果交付拒绝。

## 接入示例

```java
var grant = AgentGrant.tools(Set.of("read"), Set.of("lookup"));
try (var runtime = new AgentRuntime(
        List.of(new AgentDefinition("planner", grant, Set.of("reader")),
                new AgentDefinition("reader", grant, Set.of())),
        AgentRuntimeLimits.defaults(),
        (event, decision) -> audit.accept(event, decision))) {
    // 身份和 grant 必须来自可信认证、授权入口，不能由模型任意指定。
    var identity = SecurityContext.authenticated("tenant", "user", Set.of("read"));
    var root = runtime.startRoot("planner", identity, grant,
            Duration.ofMinutes(1), new AgentBudgetLimits(20, 100));
    try (root) {
        root.call(() -> {
            try (var child = runtime.delegate("reader", grant, Duration.ofSeconds(30))) {
                child.call(() -> runReader());
            }
            return null;
        });
    }
    var snapshot = root.budgetSnapshot();
    // snapshot.invocations() 包含根任务本身；完成的孩子仍占累计额度。
    // snapshot.protectedChecks() 是入口检查次数，不是工具成功次数。
}
```

示例中的 `audit`、`runReader()` 由业务实现。调用模型或工具时，需要 Java Agent 的对应边界适配，或者显式调用 `PolicyEngine.check`。仅建立 runtime 不会自动发现任意业务父子关系或拦截没有接入引擎的操作。完整依赖、导入和权限接入见 [多 Agent 安全](multi-agent-security.md)。

预算只能由 `startRoot` 设置，`delegate` 没有提高预算的参数。每个根任务独立持有计数，没有全局 runId 到预算的无界映射；后代句柄引用同一根句柄。结束后仍可通过任意后代的 `budgetSnapshot()` 查看最终不可变快照。

## 两种容量的区别

| 配置 | 含义 | 释放规则 |
| --- | --- | --- |
| `AgentRuntimeLimits.maxInvocations` | 一个 runtime 同时登记的执行数 | 执行结束释放 |
| `AgentBudgetLimits.maxInvocations` | 一棵根任务累计成功进入登记的执行数，含根 | 不返还；范围 1～10000 |
| `AgentBudgetLimits.maxProtectedChecks` | 一棵根任务累计受保护入口检查数 | 不返还；范围 1～1000000 |

旧版四参数 `startRoot` 保持可用，默认每根最多 10000 次累计登记、1000000 次入口检查。生产入口应显式配置符合业务工作量的预算。原有最大深度、生命周期、并发登记限制继续生效；子任务时间不能超过父任务。

未知 Agent、非法子授权、深度拒绝、非法 lifetime、runtime 并发容量拒绝都在登记扣费前失败。进入登记后即使启动审计失败也不退款，runtime 会进入持续拒绝状态。快照不含剩余实际并发数；并发登记用 `runtime.snapshot()` 查看。

## 检查预算如何扣费

`PolicyEngine` 首次调用 `DelegationGuard.begin`，先检查身份、有效委托和资源授权，再原子扣减。检测器结束后再次调用 `evaluate` 校验委托有效性，这次不扣费。

扣费的阶段：`MODEL_INPUT`、`TOOL_INPUT`、所有 `MCP_*_INPUT`、`RETRIEVAL_INPUT`、`AUGMENTATION_INPUT`、`MEMORY_READ_INPUT`、`MEMORY_WRITE`、`MEMORY_DELETE`。输出检查与生命周期事件不扣费。没有委托身份的普通上下文不适用此预算。

这是**检查尝试数**：检测器拒绝、超时、审计拒绝仍消耗已扣的额度；身份或资源授权已拒绝时不扣。多个包装层分别发起的输入检查分别计数。反复提交同一个 `eventId` 也分别扣费，避免伪造 ID 绕过限制。因此不能将它当作精确模型请求数、token 数、金额或副作用成功次数。

所有扣减与委托失效在同一个 runtime 锁内排序。第 N 次检查可扣掉最后一份额度；第 N+1 次尝试使树失效。并发耗尽时，已经扣费但尚未通过最终授权复检的检查也可能被拒绝，不保证恰好有 N 次业务操作成功。

## 耗尽与取消

| 事件 | 错误／终止原因 | 影响 |
| --- | --- | --- |
| 超出累计登记数 | `agent-budget-invocations` | 根 `BUDGET_EXHAUSTED`，活跃后代 `PARENT_REVOKED` |
| 超出入口检查数 | `agent-budget-checks` | 同上，当前操作拒绝 |
| `invocation.cancel()` | 当前节点 `CANCELLED`，后代 `PARENT_REVOKED` | 只取消本节点子树 |
| 终止审计故障 | `agent-audit-error` | 其他根也失效为 `AUDIT_FAILED`，runtime 持续拒绝 |

宿主可以持有根句柄，用户点击取消时调用 `root.cancel()`；子句柄只能直接取消其子树。句柄是同 JVM 可信能力，不能通过客户端请求传入伪造对象。跨服务身份认证和任务取消协议不属于本轮能力。

`call`／`submit` 在提交成功结果前会再次确认委托仍有效。取消先完成时，即使 Callable 随后正常返回，也不会作为成功值交付；完成先结束时，之后的取消不会改写结果或终止原因。这是本轮对旧行为的收紧：此前撤销后的 Callable 仍可能返回成功值。

取消是权限与结果层的协作式取消，不强制中断业务线程、模型请求或外部 I/O，也不回滚已经发生的副作用。`submit` 的排队任务在工作线程开始处理时检查失效，跳过任务体并异常完成 future；如果宿主执行器一直不处理队列，该 future 仍可能保持 pending。已开始的任务可能继续运行至返回或异常，再交付失败；不能据登记释放推断真实 CPU／I/O 已停止。调用返回 future 的 `cancel` 仍可使本次子树失效，但同样没有物理停止保证。

需要立即停止外部工作时，宿主应额外绑定 provider 的取消句柄、请求超时和执行器任务管理。不能把此预算用作恶意同 JVM 代码沙箱，也不能认为自由持有 root 授权入口的业务代码无法创建新根绕过预算。

## 验收与源码阅读

重点测试在 `AgentBudgetTest`：完成不退款、兄弟并发扣减、根隔离、输入仅扣一次、输出不扣、拒绝尝试扣费、重放 eventId、取消排队任务、运行中取消不泄露成功结果、子树取消及预算终止审计失败。运行 `mvn -pl agent-security-core -am test`，完整交付使用 `bash scripts/release.sh`。

建议依次阅读 `AgentBudgetLimits` → `AgentRuntime.startRoot/register/consumeProtectedCheck` → `DelegationGuard.begin` → `PolicyEngine.checkInternal` → `AgentRuntime.complete` → `AgentInvocation.execute`。预算快照用于宿主查询；生命周期审计和已有遥测能够看到 `BUDGET_EXHAUSTED` 终止原因。经 PolicyEngine 拒绝的预算异常归入结构化诊断的 CAPACITY_LIMIT，生命周期审计故障归 AUDIT_FAILURE；直接调用 runtime 的准入异常仍不自动产生诊断快照。本轮没有新增带 runId 标签的 Prometheus 指标，也没有 token／费用预算、跨进程一致扣费或任务工作线程强制取消。
