# 运行时覆盖与健康诊断

本轮提供只读快照和 Prometheus 指标，帮助接入方区分“Agent 没有安装”“框架类尚未加载”“发生插桩故障”“检测线程被占满”和“审计已不可用”。诊断不参与授权决策，也不创建 HTTP 服务，不要求 Spring。

## Java Agent 接入

业务需要引用与 Java Agent 同版本的 core 模块才能编译以下代码；普通 LangChain4j 应用使用 Agent 的拦截仍不要求增加 SDK 依赖。Spring Boot 嵌套 JAR 的共享实例已加入真实启动验证。自定义类加载器、重复加载不同版本 core 仍不在支持承诺内。

```java
import io.agentsecurity.core.health.AgentCoverage;

var coverage = AgentCoverage.global().snapshot();
System.out.println("installed=" + coverage.installed());
System.out.println("failed=" + coverage.failed());
System.out.println("supported=" + AgentCoverage.SUPPORTED_LANGCHAIN4J);
System.out.println("versionChecksPassed=" + coverage.versionChecksPassed());
System.out.println("versionChecksFailed=" + coverage.versionChecksFailed());
// 以下类名清单仅在受限运维端点展示，不作为指标标签。
System.out.println(coverage.transformedTypes());
```

| 字段 | 含义 | 不应作出的推断 |
| --- | --- | --- |
| installed | premain 完成 transformer 注册 | 所有业务代码已经受到保护 |
| failed | 已收到插桩故障信号，状态保持为 true | 查询或重新抓取能恢复引擎 |
| transformations | Byte Buddy 变换成功通知次数 | JVM 已成功定义这些类，或类内所有方法都被保护 |
| transformedTypes | 最多 128 个合法类名，每个最多 256 字符 | 全量类清单、完整调用覆盖清单 |
| omittedNames | 因容量或格式限制未收录名称的通知数 | 唯一遗漏类的数量 |
| failures | 故障信号次数 | 唯一失败类数；listener 和拒绝加载包装器可能报告同一次失败 |
| versionChecksPassed / Failed | 实际版本检查的成功/失败次数 | 唯一 ClassLoader 数；缓存命中不递增，并发首次检查可能重复 |
| detector / audit | Agent 绑定实例的执行池健康快照 | null 是健康；null 表示未绑定或当前实例不是 Agent 共享实例 |

当前支持版本常量是 1.20.0，运行时版本拒绝逻辑使用同一个常量。尚未执行任何受保护调用时，版本检查计数为零是正常的，不代表兼容性已经确认。

诊断状态的写入口服务于 Agent 初始化和插桩回调；同 JVM 任意代码可以调用，因此快照不是防篡改证明。即使人为改动诊断信息，也不会解除 Bridge 的拒绝状态。不要把诊断标志作为放行依据。

## 独立 SDK 接入

直接使用 SDK 时，没有 Java Agent 是正常的。分别查询应用拥有的 PolicyEngine 和 BoundedAuditSink：

```java
var detectorState = engine.detectorHealth();
var auditState = audit.health();
```

| 字段 | 解释 |
| --- | --- |
| active / queued | 执行池正在处理的任务和等待队列长度，近似观察值 |
| concurrency / capacity | 最大并发线程数和等待队列容量 |
| closed | 已请求线程池关闭，不保证不响应中断的任务已经退出 |
| failed | 审计不可用的粘滞状态；正常关闭审计也置为 true，结合 closed 区分。检测池无此闩锁，值为 false，不表示历史无故障 |
| timeouts | 等待执行超过预算的次数；检测入口预算已耗尽也计入 |
| errors | 检测 Future 执行异常；审计等待执行异常和 delegate 关闭异常 |
| rejected | 检测提交被关闭/容量拒绝或任务被取消；审计不可用入口拒绝、提交拒绝或任务取消 |
| interrupted | 等待线程被中断；检测入口已有中断标志也计入 |

计数累计到实例销毁，不提供重置。各项并发读取不具备跨字段原子性，不应相加当作所有业务请求的精确总量。总决策量继续使用 SecurityTelemetry 的 phase/outcome 指标。

检测池仅统计隔离执行的扩展检测器和 SPI 加载，不含在调用线程运行的内置策略、DelegationGuard 或未提交检测任务的关闭引擎拒绝。`withAdditionalDetectors()` 派生引擎共享池和统计，不能将它们的计数再次求和。自定义未包装的审计回调不自动获得这些指标。

超时不保证检测代码停止。如果插件忽略中断，timeouts 增加后 active 仍可能为 1。这正是需要暴露的故障线索；线程和队列上限仍由原有机制约束。诊断不会新增线程或执行用户回调。

## Prometheus 接入

添加可选 telemetry 模块。新接口返回独立指标文本片段，可和原有指标拼接：

```java
var coverage = AgentCoverage.global().snapshot();
String metrics = PrometheusMetrics.render(telemetry, exporter)
        + PrometheusMetrics.renderHealth(
                coverage.detector(), coverage.audit(), coverage);
```

纯 SDK 不需要报告插桩状态：

```java
String metrics = PrometheusMetrics.render(telemetry, exporter)
        + PrometheusMetrics.renderHealth(engine.detectorHealth(), audit.health(), null);
```

HTTP 端点、认证和访问控制仍由宿主负责，Content-Type 使用 `PrometheusMetrics.CONTENT_TYPE`。一个响应只渲染一组同名健康指标；多引擎宿主应明确聚合或分开暴露，不能简单拼接多个引擎产生重复样本。

新增指标前缀：

- `agent_security_detector_` / `agent_security_audit_`：active、queued、concurrency、queue_capacity、closed、failed，以及 timeouts_total、errors_total、rejected_total、interrupted_total。
- `agent_security_instrumentation_installed`、`agent_security_instrumentation_failed`。
- `agent_security_transformations_total`、`agent_security_transformation_failure_signals_total`、`agent_security_transformed_names_omitted_total`。
- `agent_security_version_checks_passed_total`、`agent_security_version_checks_failed_total`。

字段仅包含固定名称和数值；不使用工具名、类名、用户、租户、runId 等标签。未传入的执行池不输出指标，避免以零伪装未知状态。

## 建议的接入验收

1. 启动应用，核对 installed=true；在执行受保护调用前，不以变换数量或版本检查零值判断故障。
2. 执行目标业务路径，查看预期组件类的变换通知和版本检查。再执行一条明确违规的请求，核对实际工具/模型副作用为零；变换通知本身不能替代这个验收。
3. 注入慢插件，检查 timeouts 增加；插件忽略中断时确认 active 仍可见，队列不超配置上限。
4. 注入审计写入异常，检查 failed=true，后续调用持续拒绝；确认诊断查询不会恢复放行。
5. 在真实部署方式下抓取指标，确认没有敏感标签和重复样本。

本轮增加核心诊断测试及指标测试，并在 Boot 现有独立 JVM 场景检查共享 Agent 状态和插件超时计数。本轮完整发布验证为 320 项测试零失败，四个运行时 JAR 隔离重建一致；明细见 [生产验收记录](production-readiness.md)。

## 后续迭代

本轮交付的是覆盖诊断基础，不是方法级完整覆盖证明。自动列出未适配方法、给出各边界覆盖报告，以及把插桩前/引擎外拒绝统一成诊断事件，仍待实现。完整覆盖边界继续以 [生产验收清单](production-readiness.md) 为准。

远程检测客户端已实现，见 [远程检测接入](remote-detector.md)。策略版本与原子更新也已提供基础能力，见 [策略版本管理](policy-versioning.md)。后续推进 MCP 防护，再扩展多 Agent 预算及跨服务委托。长期压力和故障恢复验收贯穿每次运行时变更。
