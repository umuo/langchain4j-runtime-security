# 可观测性数据收集

核心收集器提供进程内安全指标和脱敏关联记录，不依赖 Spring，不启动 HTTP 服务或主动发送网络请求。可选 `agent-security-telemetry` 模块可显式启动网络日志导出，并提供 Prometheus 文本渲染。旧构造方法默认关闭收集；启用后，安全检查线程只更新固定数量的计数器并尝试向有界队列写入记录，业务在独立线程中拉取和导出。

## 已实现的数据

| 数据 | API | 含义 |
| --- | --- | --- |
| 检查／生命周期事件数量 | `snapshot().metrics()` | 按固定 `phase` 和 `outcome` 枚举分组；指标不采样 |
| 耗时分布 | `Metric.durationBuckets()` | 五个独立区间：≤1ms、(1ms,10ms]、(10ms,100ms]、(100ms,1s]、>1s，单位纳秒 |
| 队列状态 | `snapshot().queued()`、`dropped()` | 当前关联记录数、队列满累计丢弃数；采样跳过不算丢弃 |
| 父子关联 | `drain(maximum)` | 时间戳、事件 UUID、阶段、结果、耗时、runId、invocationId、parentInvocationId |

结果分类为 `ALLOW`、`DENY`、`DETECTOR_FAILURE`、`AUDIT_FAILURE`、`INTERNAL_ERROR`。引擎使用 `audit-error` 和 `detector-` 规则前缀区分故障；插件不要使用这些保留名称表达普通业务拒绝。遥测不导出任意规则名称，因此不会随插件动态规则增加指标维度。定位具体规则请关联原有审计中的事件 UUID。

决策耗时覆盖 `PolicyEngine.check`，包含检测和审计确认；生命周期耗时仅为该次生命周期审计耗时，**不是 Agent 任务总时长**。本版本没有单检测器耗时、活跃 Agent 数、委托深度或完整 span。生命周期沿用 `AgentRuntime` 原有语义：根结束／撤销使子树失效，但不为每个后代补发结束事件，过期采用惰性清理。因此不能靠开始数减结束数计算精确活跃任务数。

## 独立 SDK 接入

以下示例可放入使用 `agent-security-core` 的普通 Java 项目。实际工程中应复用应用级收集器及引擎；审计回调应替换为原有可靠审计实现。

```java
import io.agentsecurity.core.*;
import io.agentsecurity.core.delegation.*;
import io.agentsecurity.core.telemetry.SecurityTelemetry;
import java.time.Duration;
import java.util.List;
import java.util.Set;

public class TelemetryExample {
    public static void main(String[] args) throws Exception {
        // 最多缓存 1024 条关联记录，每个事件都尝试保留；指标始终全量累计。
        var telemetry = new SecurityTelemetry(1024, 1);
        var grant = AgentGrant.tools(Set.of("read"), Set.of("lookup"));
        var definitions = List.of(
                new AgentDefinition("planner", grant, Set.of("reader")),
                new AgentDefinition("reader", grant, Set.of()));
        try (var engine = new PolicyEngine(List.of(), (event, decision) -> {},
                     DetectionLimits.defaults(), telemetry);
             var runtime = new AgentRuntime(definitions, AgentRuntimeLimits.defaults(),
                     (event, decision) -> {}, telemetry)) {
            // 认证与根授权仍由可信宿主提供，不接受模型提供的身份。
            var identity = SecurityContext.authenticated("tenant", "user", Set.of("read"));
            var root = runtime.startRoot("planner", identity, grant, Duration.ofMinutes(1));
            root.call(() -> {
                var child = runtime.delegate("reader", grant, Duration.ofSeconds(30));
                return child.call(() -> {
                    engine.check(new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "lookup", ""));
                    return null;
                });
            });
        }
        System.out.println(telemetry.snapshot());
        telemetry.drain(100).forEach(System.out::println);
    }
}
```

`withAdditionalDetectors` 派生引擎共享原收集器。收集器没有后台线程及外部连接，不需要关闭；引擎或调度器关闭后仍可读取最后的记录。

## Java Agent 接入

在原策略 properties 文件中启用：

```properties
telemetry.enabled=true
```

Java Agent 将安全检查写入 `SecurityTelemetry.global()`。全局实例容量为 256，每个事件都尝试保留；业务侧从同一实例读取。若还需要父子生命周期记录，创建调度器时显式传入该实例：

```java
var telemetry = SecurityTelemetry.global();
var runtime = new AgentRuntime(definitions, limits, auditSink, telemetry);
```

`telemetry.enabled` 默认 `false`，只控制 Agent 创建的检测引擎，不会自动配置应用自行创建的引擎或调度器。开关是启动配置。Boot 集成测试验证 Agent 与业务读取的是同一个全局实例；自定义隔离 ClassLoader 可能持有不同的核心类副本，不承诺共享。

## 扩展导出与运行约束

导出适配器可以定时调用 `snapshot()` 读取指标，再调用 `drain(100)` 批量获取关联记录。应在宿主自己的单独线程调度，设置网络超时、有限重试和重试缓存上限。不要在 `Detector` 或审计回调内执行网络导出。适配器失败后由宿主处理和告警，不回传到安全决策。

`drain` 是破坏性读取，不提供确认、重放或持久化。多个消费者会竞争分配记录；若要向多个后端发送，应由一个消费者读取后再分发。拉取后导出失败不会自动重新入队，也不计入收集器的 `dropped`；导出适配器必须另记失败／丢弃计数。进程退出时内存记录可能丢失。

采样参数 `sampleEvery=10` 表示按并发入队序号每十个事件取一个，不是按完整任务采样，可能出现缺少父节点的调用树。需要尽量完整的关联关系时使用 1，并合理安排消费频率；即便如此队列满、进程退出也会导致缺失。关闭阶段应先停止新业务并等待在途任务，再最后拉取；本版本不承诺退出自动刷新。

快照各项计数不是原子事务；并发期间直方图合计与计数可能短暂不一致，静止后收敛。计数为进程内累计值，重启归零。导出 Prometheus 风格累计直方图时，需要将各独立区间累加，不能直接将数组当累计桶。

## 隐私与安全语义

记录不包含 `SecurityEvent`／`SecurityContext` 对象引用，也没有提示词、输出、工具名称、参数、资源标识、租户、用户、权限或异常消息。UUID 仅用于关联，不能作为鉴权依据。关联数据仍应受访问控制、保留期限和传输保护约束。

指标标签只使用阶段与结果枚举，禁止把事件、run 或 invocation UUID 加入指标标签。UUID 应作为日志／调用链字段。固定指标总数上限为阶段数乘结果数，与工具名、规则数量和业务用户数量无关。

遥测丢弃不阻断业务；**安全审计失败仍阻断操作**。本版本不会修改现有 JSONL 审计 schema 3，也不会用遥测替代审计。对尚未插桩的操作、引擎外初始化错误、未进入生命周期审计的委托失败，不保证有遥测事件。

## 后续需求方向

| 优先级 | 需求 | 验收标准 |
| --- | --- | --- |
| P0 | 导出适配器后续验收 | 已有 Prometheus 文本与 OTLP/HTTP 日志；补真实 Collector／监控后端、TLS 和长期断网验收 |
| P0 | 精确生命周期与调用链 | 每个子任务有明确完成／过期／撤销原因，覆盖异步结束；完整任务采样；可验证活跃数与深度 |
| P0 | 性能和长期压力验收 | 测量启用前后吞吐、P95/P99、堆占用；慢消费者和长时间断网资源有界 |
| P1 | 检测／审计／插桩健康指标 | 区分检测执行、审计等待、队列饱和与转换失败；说明未覆盖路径 |
| P1 | 面向业务的安全看板和告警 | 能由拒绝率或超时异常定位 run 和父子执行，并跳转审计规则；配置告警阈值 |
| P1 | 跨进程认证与委托 | 可信签发方、受众绑定、短期凭据、权限收窄、重放防护、密钥轮换和服务端授权 |
| P2 | 远程检测和覆盖扩展 | 有界调用远程检测，验证 MCP 等新增拦截边界，建立误报／漏报评估集 |

以上是发展规划，不是当前已支持的能力。跨服务 trace context 仅用于关联，不能替代委托凭据和认证。

## 可选导出模块

新增 `io.agentsecurity:agent-security-telemetry:0.1.0-SNAPSHOT`，依赖 core 与 Jackson Core，网络请求使用 JDK HttpClient。它不被打包进 Java Agent，也不通过策略文件自动开启网络请求；宿主显式添加依赖和创建导出器。构建本地依赖可执行 `mvn -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 -pl agent-security-telemetry -am install`。

### OTLP/HTTP 日志

这是协议级 JSON 日志适配器，不是完整 OpenTelemetry SDK 或 trace exporter。父子执行 UUID 使用日志属性传输，不作为 W3C traceId/spanId，也不传播认证身份。请求发送至完整 URL；例如本机 Collector 的 `/v1/logs`。

```java
import io.agentsecurity.core.telemetry.SecurityTelemetry;
import io.agentsecurity.telemetry.OtlpLogExporter;
import io.agentsecurity.telemetry.PrometheusMetrics;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;

public class ExportExample {
    public static void main(String[] args) throws Exception {
        // 配合 Java Agent 的 telemetry.enabled=true。
        var telemetry = SecurityTelemetry.global();
        var http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        // 此示例不含凭据；生产需要时通过可信配置传入 Authorization 等 Header。
        try (var exporter = new OtlpLogExporter(
                telemetry, http, URI.create("http://127.0.0.1:4318/v1/logs"),
                "order-agent", Map.of(), Duration.ofSeconds(1),
                Duration.ofSeconds(3), 128, 3)) {
            // 在这个作用域内运行并等待实际业务任务。
            // 业务现有 /metrics 端点可返回以下文本，并设置 PrometheusMetrics.CONTENT_TYPE。
            String metrics = PrometheusMetrics.render(telemetry, exporter);
            System.out.print(metrics);
        }
    }
}
```

普通 SDK 使用自建 `SecurityTelemetry` 实例传给引擎、调度器和 exporter 即可；不要让 exporter 读取 global，而业务写到另一个实例。一个收集器应仅有一个日志消费者。监控抓取调用 `snapshot()`，不会消费日志队列。

导出器构造成功后立即启动一个 daemon 工作线程，不在安全检查线程执行网络请求。一次最多保留一个批次和一个在途请求；每批 1–256 条，每批最多尝试 1–3 次，轮询间隔 10ms–60s，每次请求总等待时间 10ms–30s（包括响应体）。请求体上限 1 MiB，响应体在接收过程中限制为 16 KiB。核心队列仍然有界；持续故障会发生可见的丢弃，不无限缓存。

HTTP 429/502/503/504 与连接故障可有限重试；没有 `Retry-After` 时采用退避并加抖动。有合法 `Retry-After` 时遵循秒数或日期；若要求等待超过 30 秒，丢弃该批以保持本适配器的重试等待上限。400/401/其他永久错误、重定向、非法 JSON、超限响应不重试。HTTP 200 的部分成功响应按拒收数量分别统计成功／丢弃，不重发整批。超时可能发生在远端已接收之后，重试可能重复，后端可用 `security.event.id` 去重；不保证恰好一次。

导出器只接受禁用重定向的 HttpClient，避免跨目标转发认证头。endpoint 与 headers 必须来自可信宿主配置，不能由模型或用户请求直接控制。生产跨网络应使用 HTTPS；TLS、代理、HttpClient 执行器与连接资源由宿主管理。导出器不拥有或关闭传入的 HttpClient；创建应用级共享客户端，不要按请求创建导出器。自身线程数量有界不等于替宿主客户端提供线程池限制。

`close()` 设置停止并中断在途等待，不等待远端，也不自动刷新。已取出的未确认批次会被计入 exporter dropped；核心队列中尚未取出的记录仍保留在收集器。生产关闭应停止新业务、等待业务结束，再等待 `queued=0` 和 `pending=0`（设置宿主总等待上限），最后关闭 exporter。进程崩溃和强制退出不保证统计与投递完整。

### Prometheus 文本与健康指标

`PrometheusMetrics.render(telemetry, exporter)` 生成 text 0.0.4，宿主负责 HTTP 路由、访问控制和抓取配置。只需要安全指标时 exporter 可传 `null`。适配器不会自行监听公网或默认注册 Spring Controller。

| 指标 | 含义 |
| --- | --- |
| `agent_security_events_total{phase,outcome}` | 检查／生命周期累计次数 |
| `agent_security_check_duration_seconds` | 累计桶、count 和 sum；sum 来自新增的 `Metric.durationNanosTotal` |
| `agent_security_telemetry_queued` | 核心队列积压 |
| `agent_security_telemetry_dropped_total` | 核心队列满造成的丢弃 |
| `agent_security_export_attempts_total` | 已尝试请求数，包括重试 |
| `agent_security_export_failures_total` | 故障次数，包含部分拒收和解析失败 |
| `agent_security_export_timeouts_total` | 请求或响应体等待超时次数 |
| `agent_security_export_accepted_total` | 服务端响应确认接收的记录数 |
| `agent_security_export_dropped_total` | 永久失败、耗尽重试、部分拒收及关闭取消的记录数 |
| `agent_security_export_pending` | 已拉取但尚未确认或丢弃的记录数 |

阶段和结果是固定枚举；指标不携带用户、任意工具名或关联 UUID。直方图的 `+Inf` 与 count 从同一组桶生成；sum、事件计数及健康快照在并发期间仍非原子。生命周期对应的是审计耗时，不要把这条直方图当作 Agent 总运行时长。

建议首先对 `rate(agent_security_export_failures_total[5m])`、两种 dropped 的增长及持续 queued 积压配置告警，再按 phase/outcome 观察安全拒绝率。阈值需要根据实际流量确定，本项目不预设 SLA。

### 协议依据与验证范围

实现依据 [OTLP 传输规范](https://opentelemetry.io/docs/specs/otlp/) 的 JSON 日志、部分成功和重试规则，以及 [Prometheus 文本格式](https://prometheus.io/docs/instrumenting/exposition_formats/)。本地测试使用真实 HTTP 客户端和模拟协议端点，覆盖 JSON、认证头、脱敏、临时／永久失败、部分成功、超限、超时与关闭。尚未在真实 Collector、Prometheus 服务和生产 TLS 环境完成端到端验收；不能把协议端点测试写成监控平台验收通过。
