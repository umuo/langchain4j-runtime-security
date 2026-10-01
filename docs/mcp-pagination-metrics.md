# MCP 分页预算与容量诊断

本迭代限制发现列表在分页累积期间的资源使用，并为传输/分页超限提供固定维度的进程内计数和 Prometheus 文本输出。固定支持 LangChain4j core 1.20.0、MCP 1.20.0-beta30 的 DefaultMcpClient。

## 1. 配置预算

```properties
# 单个 HTTP 响应体 / stdio 单行的原始字节上限（已有配置）
mcp.max.response.bytes=1048576

# 新增：每次实际分页查询的累计预算
mcp.pagination.max.pages=16
mcp.pagination.max.items=128
mcp.pagination.max.json.bytes=1048576
```

| 配置 | 默认 | 合法范围 | 执行时机 |
| --- | --- | --- | --- |
| max.pages | 16 | 1～256 | 创建下一页请求前，达到上限则不发出该请求 |
| max.items | 128 | 1～128 | 页面解析后、加入总列表前 |
| max.json.bytes | 1048576 | 1～16777216 | 调用类型化页面解析器前 |

表中后三项均带 `mcp.pagination.` 前缀。它们是 Java Agent 启动配置，不是 LocalPolicy/PolicyCompiler 属性，不随策略版本热更新。条目数上限不能超过已有发现结果的 128 项上限。

保护 listTools、listResources、listResourceTemplates、listPrompts。instructions 不分页。每次框架实际调用内部 fetchPaginatedList 时创建独立预算；缓存命中不创建预算，但发现入口仍重新鉴权。

“累计 JSON 字节”是类型化页面解析器收到的 JSON 字符串按 UTF-8 编码计算的长度，包含 JSON 包装与游标，不是所有网络字节：SSE event/data framing 不在此计数内，传输层可能重序列化 JSON。计算长度时不额外创建整份字节数组。框架在此之前可能已解析错误/协议字段，所以它不替代单页传输限制。

## 2. 拒绝与恢复语义

返回的 nextCursor 必须为 null 或非空字符串，最多 1024 个 UTF-16 code unit。重复游标立即拒绝，包含 A → B → A 的循环；已见游标只保留在本次查询内，数量受页数预算约束。持续返回空列表但给出新游标，也会被页数上限终止。

| ruleId | 含义 |
| --- | --- |
| mcp-pagination-pages | 下一页将超过页数预算 |
| mcp-pagination-items | 当前页会使累计条目超限 |
| mcp-pagination-bytes | 当前 JSON 会使累计字节超限 |
| mcp-pagination-cursor | 重复、空或过长游标 |
| mcp-pagination-shape | 页面结构、反射访问或 JSON 字符形状无法安全适配 |

条目/游标超限时当前页已由客户端解析，但不会加入总列表；已经接受的前几页也不会作为部分成功结果返回。正常成功的列表仍经过发现出口的内容检测。新的查询拥有新预算，分页超限不把客户端标记为永久不可用。传输原始响应超限仍遵循上一轮的粘滞故障语义，需重建传输和客户端。

本轮没有新增整个查询的墙钟总超时。原有框架每页超时仍生效，宿主需设置有限的 toolExecutionTimeout、resourcesTimeout、promptsTimeout。单页解析器的对象分配/CPU、第三方监听器、原始日志和远程进程资源仍不受这三个累计预算完整约束。

分页页对象是固定版本的包内 record，适配器使用受限反射访问这两个已知 accessor。无法访问时拒绝，不通过关闭检查兼容。JPMS 强封装、自定义客户端/传输和其他 LangChain4j 版本未验收。

## 3. 在代码中获取诊断

```java
import io.agentsecurity.core.health.McpDiagnostics;
import io.agentsecurity.telemetry.PrometheusMetrics;

McpDiagnostics.Snapshot snapshot = McpDiagnostics.global().snapshot();
String metrics = PrometheusMetrics.renderMcp(snapshot);
// 与现有 render / renderHealth 的文本拼接，由宿主自己的指标端点返回。
```

快照在 core 中，不依赖 Spring。Prometheus 文本输出需要 telemetry 模块。Java Agent 写入进程内全局诊断；它不自动启动 HTTP 服务，也不自动发送 OTLP。不要在同一个指标端点重复拼接 renderMcp 的结果。

快照只包含固定枚举与数值，不保存服务名、工具名、租户、URI、游标、正文或异常消息。快照不可变，但不同计数器的并发采样不是同一原子时间点。公开诊断方法供可信宿主使用，不是防篡改审计；强制审计继续走既有独立通道。

零值不能证明 Agent 已正确安装，应结合 AgentCoverage 的 installed/failed/版本检查和真实验收。多个应用副本由指标系统按实例聚合。

## 4. 指标含义

| 指标（统一带 agent_security_mcp_ 前缀） | 含义 |
| --- | --- |
| limit_rejections_total{reason} | 固定原因的容量拒绝计数 |
| transport_failures_total | 首次因容量限制失效的传输状态数量；多客户端共享同一传输只记一次 |
| failed_state_checks_total | 检查已失效状态并被拒绝的次数，可能含内部读取检查，不等同于业务调用数 |
| pagination_started_total | 实际分页查询开始数，不包括缓存命中 |
| pagination_completed_total | 分页查询正常返回数，不保证最终发现内容检测允许 |
| pagination_failed_total | 分页查询失败数，包含容量、解析、网络和其他异常 |
| pages_requested_total | 开始调用页面请求工厂的次数，工厂/传输失败时不一定实际发送到服务器 |
| pages_accepted_total | 满足本轮累计预算并交给框架聚合的页数 |
| items_accepted_total | 上述已接受页的条目总数 |
| json_bytes_accepted_total | 上述已接受页的 JSON UTF-8 字节总数 |

每项均为进程生命周期 counter，重启归零。接受页数/条目数不是安全策略 ALLOW 数；前页接受后整次查询仍可能失败。

reason 只有以下六项：

- HTTP_RESPONSE_BYTES
- STDIO_LINE_BYTES
- PAGINATION_PAGES
- PAGINATION_ITEMS
- PAGINATION_BYTES
- PAGINATION_CURSOR

同一传输只有首次容量超限增加对应原因计数；后续检查单独计入 failed_state_checks。一次分页查询在首次容量拒绝时计一次原因；重试查询是新的查询，可能再次计数。mcp-pagination-shape 属于非容量失败，会增加 pagination_failed，但不伪装成上述容量原因。

例如可观察最近 5 分钟新增的分页超限：

```promql
sum by (reason) (
  increase(agent_security_mcp_limit_rejections_total{reason=~"PAGINATION_.*"}[5m])
)
```

传输首次超限后应关闭故障客户端、查明响应来源与配置，再决定是否重建；不要简单自动增大预算。分页失败增多而 limit 原因不增长时，应结合异常类型检查网络、解析或版本适配问题。

## 5. 如何验收

McpTransportIT 在真实本机 HTTP JSON、POST 响应 SSE、stdio 中加入：四种目录正常两页合并、页数超限前停止第三个请求、累计条目/JSON 字节超限、重复/过长游标、无限空页，以及同一客户端重试获得新预算。

同时核对诊断快照与服务端请求日志。页数超限重试场景每次最多两页，两次调用共四个业务请求，pagination_failed 与 PAGINATION_PAGES 均为 2，transport_failures 为 0。响应字节超限仍只记一次传输故障，随后调用在入口拒绝，服务端不会收到第二个工具请求。

单元测试覆盖 UTF-8 多字节/代理对精确边界、拒绝页不计入 accepted、结束计数不重复、并发诊断计数、不可变快照和 Prometheus 固定标签。完整执行命令仍为 `bash scripts/release.sh`。

后续方向：整次分页查询的总截止时间、异常结果的统一结构化诊断、MCP 认证/重连故障矩阵。上一轮偶发冷启动错误的根因仍未完全确认，保留 20 次冷启动回归与诊断，不把本轮通过当作根因已消除的证明。
