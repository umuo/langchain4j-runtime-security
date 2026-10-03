# 结构化故障诊断：从一个错误定位到父子调用

本能力提供统一故障快照、有界进程内队列、固定维度指标和 JSON v1 编码。core 不依赖 Spring；Java Agent 自动接入已支持的 MCP 边界和策略引擎，不启动管理端口或导出线程。

## 1. 先看能回答什么

| 排查问题 | 字段与使用方法 |
| --- | --- |
| 这是同一个拒绝吗？ | `id` 为诊断 UUID；同一 SecurityBlockedException 跨已接入边界传播时复用 |
| 哪类问题？ | `category`：策略拒绝、检测器故障、审计故障、超时、容量限制、不支持、传输故障、取消、执行故障、插桩故障 |
| 哪类操作、哪一步失败？ | `boundary` 为 MODEL、TOOL、MCP_TOOL、MCP_RESOURCE、MCP_PROMPT、MCP_DISCOVERY、RETRIEVAL、AUGMENTATION、MEMORY、AGENT 或 UNKNOWN；`stage` 见下文 |
| 哪个父子 Agent？ | `runId`、`invocationId`、`parentInvocationId`、`depth`，用 invocationId 回查宿主的 Agent 登记记录 |
| 对应哪个检测事件？ | `eventId` 关联原审计事件；`phase` 标识已知输入/输出检查阶段，没有真实事件时 eventId 留空 |
| 哪条规则、哪个策略版本？ | `ruleFingerprint`、`policyFingerprint` 为标识的 SHA-256，可用同一个 fingerprint API 查询 |

`stage` 只有 POLICY_EVALUATION、MCP_INPUT、MCP_EXECUTION、MCP_OUTPUT、INSTRUMENTATION。策略引擎已生成最终拒绝时，记录保留 POLICY_EVALUATION 及准确的输入/输出 phase，不被外层 MCP Advice 覆盖。MCP 执行阶段没有检测事件，phase/eventId 留空，但 boundary 仍区分目录、工具、资源和提示词。

这不自动发现父子关系：宿主必须通过 AgentRuntime 签发委托并正确传播 SecurityContext。没有上下文时关联字段为空；不存在可信的 agent 名称自动推断。UUID 放在关联记录中，不作为 Prometheus 标签。

## 2. 直接读取拒绝异常

```java
try {
    engine.check(event);
} catch (SecurityBlockedException denied) {
    FailureRecord failure = denied.diagnostic();
    if (failure != null) {
        // 只向你自己的诊断通道交付该不可变快照。
        UUID diagnosticId = failure.id();
        UUID invocationId = failure.invocationId();
    }
    throw denied; // 拒绝后不能继续执行受保护操作
}
```

类型来自 `io.agentsecurity.core.diagnostics`，异常来自 `io.agentsecurity.core`。原来的 `ruleId()`、异常类型和拒绝行为保持兼容。手工创建、尚未经过接入边界的异常，diagnostic() 返回 null。通过异常读取快照不消费队列；即使队列已满，这个快照仍可读取。

同一安全异常只接受第一次最终诊断。通过 CompletionException 等 cause 包装传播时，收集器最多查找 8 层；循环 cause 不会无限遍历。普通非安全异常按边界记录，不承诺跨不同边界的全局去重；不维护持有 Throwable 的全局索引。固定版本中 listTools/listResources/listResourceTemplates 的无参调用转调受保护重载，普通执行异常会记录两个边界；listPrompts 的对应路径记录一个。

## 3. 收集与导出

```java
import io.agentsecurity.core.diagnostics.FailureDiagnostics;
import io.agentsecurity.telemetry.FailureJson;
import io.agentsecurity.telemetry.PrometheusMetrics;

FailureDiagnostics diagnostics = FailureDiagnostics.global();
// 在宿主的导出任务中读取，JSON 编码单批最多 1024 项。
String json = FailureJson.encode(diagnostics.drain(128));
// 将 json 交付给宿主已有的日志存储或 HTTP 导出通道。
String metrics = PrometheusMetrics.renderFailures(diagnostics.snapshot());
```

全局队列固定为 256 项。独立 SDK 收集器可用 `new FailureDiagnostics(capacity)` 创建，容量范围 1～65536；内置 PolicyEngine 和 Java Agent 当前固定写入 global，独立实例供宿主自己的扩展边界使用，不会自动替换全局实例。

业务线程仅做有界字段投影、计数和 offer，不等待队列空间、不调用宿主导出回调或网络。队列满时丢弃新记录，累计指标继续增长。drain 是破坏性读取，多个消费者会分走记录；导出失败后的重试、持久化和关闭刷新由宿主管理。当前 OtlpLogExporter 仍只消费原 SecurityTelemetry，尚未自动消费此故障队列。不要把新增 JSON v1 当作 OTLP JSON 请求直接发送。

JSON 顶层为 `schemaVersion: 1` 与 `failures` 数组。只编码本页列出的白名单字段，不反射序列化 Throwable、SecurityEvent 或 SecurityContext。无值字段省略，空批次合法。

## 4. 指标与告警

| 指标 | 类型 | 含义 |
| --- | --- | --- |
| agent_security_failures_total{category,stage} | counter | 已记录的故障次数，只有固定枚举标签 |
| agent_security_failure_records_dropped_total | counter | 因队列满而丢弃的关联记录数 |
| agent_security_failure_records_queued | gauge | 当前等待消费的记录数量 |

```promql
sum by (category, stage) (increase(agent_security_failures_total[5m]))
```

```promql
increase(agent_security_failure_records_dropped_total[5m]) > 0
```

这些指标与原有 `agent_security_mcp_*` 容量计数、SecurityTelemetry 检测次数有不同计数对象，不能相加得到“任务失败数”。同一任务可发生多个故障。快照不是跨计数器的原子事务；公开 API 供可信宿主使用，不是防篡改审计。

## 5. 规则、版本与隐私边界

```java
String expectedRule = FailureDiagnostics.fingerprint("mcp-pagination-timeout");
String expectedVersion = FailureDiagnostics.fingerprint("v12");
```

规则和版本不以原文输出，避免插件把敏感内容放进看似合法的标识中。指纹只处理最多 256 个 UTF-16 单元，超长或 null 输入返回 null；输出完整 64 位十六进制 SHA-256。指纹不是加密，低熵值仍可被字典枚举，不能将其用作凭证或完全匿名化保证。

PolicyEngine 的最终拒绝绑定实际选中的版本快照。即使审计期间已发布新版本，故障记录仍关联本次检测使用的旧版本。未使用 VersionedDetector 时 policyFingerprint 为空，不猜测宿主静态审计配置；版本快照加载失败时沿用引擎的 unresolved 标识指纹。MCP 引擎外的分页、传输或形状故障不绑定某个策略版本，版本为空。

关联记录不包含：模型输入输出、工具参数、服务器错误文本、堆栈、URI、HTTP 凭据、tenantId、principalId、原始 Agent/操作名称。原业务异常本身可能仍包含第三方错误文本；不要为使用本功能而把整个异常直接序列化。

## 6. 当前自动覆盖范围

- 所有经过 PolicyEngine 最终拒绝的模型、工具、RAG、memory、委托权限等检查，包括检测器超时和强制审计失败。
- 固定 LangChain4j core 1.20.0 / MCP 1.20.0-beta30 的工具、资源、提示词、目录入口，以及成功返回后的适配和检测失败。
- 上述 MCP 方法体异常、分页容量与总时间预算失败；异步工具回调使用入口捕获的身份。
- 插桩失败的进程内故障记录，不附带类型名、ClassLoader 或原异常对象。类无法定义时，应用可能尚未启动，宿主来不及导出记录；已有 stderr 诊断仍有必要。

已知 SDK ruleId 通过固定映射分类；未识别的安全拒绝归 POLICY_DENIED。远程检测器的超时、容量、服务故障与实际 remote-denied 拒绝分别分类。普通 TimeoutException/HttpTimeoutException、CancellationException、IOException 有相应分类，其余为 EXECUTION_FAILURE。未知服务端错误不会根据任意消息文本推断为认证失败或协议攻击。

尚未覆盖所有模型/RAG/memory 的引擎外适配异常、所有 AgentRuntime 生命周期异常、自定义传输内部后台故障、脱离调用上下文的响应读取，以及跨 JVM 聚合。原 MCP 容量指标可记录传输级故障；只有故障到达已接入边界，才形成关联记录。原始失败原因如果已被框架吞掉，不能据此接口恢复。

本能力不替代强制审计，不扩展拦截覆盖范围，也不实现认证或跨服务身份签发。

## 7. 如何验收

`FailureDiagnosticsTest` 验证队列溢出、同一异常 100 次并发传播去重、版本发布竞争下的诊断版本、审计失败拒绝、父子身份、循环 cause 和字段约束。`FailureExportTest` 验证 JSON 与固定标签不泄露正文/身份；`McpFailureBridgeTest` 验证异步线程身份恢复、交付前记录和取消传播。

真实 HTTP JSON、POST SSE、stdio 矩阵中的拒绝场景检查规则指纹与关联数据；分页超时检查 TIMEOUT/MCP_EXECUTION。新增四类目录 × 三种传输的 JSON-RPC 错误场景，验证原异常保留、产生执行阶段诊断、错误文本不被复制。

完整验收运行 `bash scripts/release.sh`，具体测试数量与环境见 [生产验收记录](production-readiness.md)。下一项按计划推进 MCP 认证与连接故障治理，然后是多 Agent 共享预算与任务树取消。
