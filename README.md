# Agent Security：LangChain4j 运行时拦截原型

独立安全 SDK 内核 + `-javaagent` 自动插桩。基础内容／工具策略只需在启动时加载 Agent 和策略文件；用户／租户权限策略另需应用在认证入口提供可信身份，无需改写 LangChain4j 调用。

当前处于 **固定 LangChain4j 1.20.0 的生产化开发阶段**，尚未达到全部生产验收要求。测试使用真实 LangChain4j AI Services / 工具执行器、官方模型客户端和本机 HTTP/SSE 端点，不调用外部模型、不需要 API key。源码按 Java 17 编译，当前验证运行环境是 JDK 21。完整缺口见 [生产验收清单](docs/production-readiness.md)。

## 快速运行

在项目根目录执行（需要 Maven 3.6.3+；首次构建访问 Maven Central）：

```bash
bash scripts/verify.sh

# 没有 Agent：mock 邮件工具执行一次
java -jar demo/target/agent-security-demo.jar tool

# 启用 Agent：拒绝邮件工具，工具执行次数为零
bash scripts/demo.sh tool

# 合法查询正常完成
bash scripts/demo.sh allowed

# 检查模型请求、模型输出、工具返回
bash scripts/demo.sh input
bash scripts/demo.sh output
bash scripts/demo.sh tool-output
bash scripts/demo.sh stream-output
bash scripts/demo.sh reactive-output
bash scripts/demo.sh reactive-allowed

# RAG 检索前／检索结果拒绝，以及正常放行
bash scripts/demo.sh rag-input
bash scripts/demo.sh rag-output
bash scripts/demo.sh rag-allowed

# 启用结构化工具策略：非法参数执行次数为零；合法参数正常执行
bash scripts/demo.sh tool-args-foreign config/tool-demo.properties
bash scripts/demo.sh tool-args-allowed config/tool-demo.properties
```

预期关键结果：

```text
# 无 Agent
RESULT scenario=tool blocked=false modelCalls=2 toolCalls=1

# 有 Agent
RESULT scenario=tool blocked=true modelCalls=1 toolCalls=0

# 正常放行
RESULT scenario=allowed blocked=false modelCalls=2 toolCalls=1
```

接入普通 Java 应用的启动方式：

```bash
java -javaagent:/absolute/path/agent-security-javaagent.jar=/absolute/path/policy.properties \
  -jar your-app.jar
```

无需添加 LangChain4j 包装代码。必须保证运行路径位于下表的支持范围内。Spring Boot 4.1.1 可执行 JAR（nested JAR ClassLoader）与应用检测器 SPI 已有测试；自定义隔离 ClassLoader、JPMS、GraalVM native image 尚未验证。Agent 必须早于任何会加载 LangChain4j 类的其他 Agent；发现类已加载时拒绝启动，防止遗漏插桩。

## 当前覆盖范围

| 路径 | 状态 |
| --- | --- |
| `ChatModel.chat/doChat` 请求与返回 | 已实现；文本消息、工具返回文本、AI 工具调用参数进入检测 |
| `ChatModel.chatAsync/doChatAsync` 请求与返回 | 已实现；拒绝返回失败的 future；返回检查随 future 完成；取消向源 future 传播 |
| AI Services 的 `@Tool` 与自定义 `ToolExecutor` | 调度入口执行前／返回后检查；包含框架中的 lambda executor |
| 直接调用普通具名 `ToolExecutor` 实现 | 对匹配的方法插桩；包含 `DefaultToolExecutor` |
| 工具并发调度、异步 AI Services | 已接入对应入口；不保证一批并发工具的原子性，其他已放行工具可能已经执行 |
| 回调式 `StreamingChatModel` | 输入检查；正文、thinking、工具回调缓冲到最终校验通过后释放；跨 chunk 检查；输出拒绝通过 `onError` 交付（输入拒绝可同步抛出） |
| Reactive `Flow.Publisher` 模型入口 | 已实现固定 1.20.0 的模型事件流；每次订阅检查输入，输出完整校验后按 demand 交付；支持取消、并发 request 和超时 |
| RAG | 已实现 ContentRetriever／RetrievalAugmentor 同步与 future 前后检查；具名直接调用及指定框架入口的 lambda 分发；查询、结果正文／文档元数据检查；不自动落实数据源 ACL，详见 [边界](docs/rag-security.md) |
| MCP | 固定版本工具、资源、提示词边界与精确授权；[MCP 工具](docs/mcp-security.md)、[资源/提示词与传输验收](docs/mcp-content-security.md)；[发现与响应容量](docs/mcp-discovery-limits.md) 已适配，订阅未覆盖 |
| ChatMemory / ChatMemoryStore | 读前授权／读后消息检查、批量写入前检查、删除前授权，同步／future 和指定框架分发入口；逐会话 ACL 需应用 SPI，详见 [接入](docs/memory-security.md) |
| Embedding、工具描述、多模态 | 未实现专用防护；用户／工具非文本内容显式拒绝；不提供图像／音频检测 |
| 直接调用业务工具方法、绕过 LangChain4j 的 HTTP / SQL / 文件操作 | 不覆盖 |
| 手动直接调用 lambda executor 的 `execute` | 隐藏类插桩未支持；通过 AI Services 调度时受控 |

Java Agent 只能保护匹配并成功增强的入口，不是 JVM 沙箱。当前针对正常应用中的 Agent 决策做约束，不抵御同 JVM 中可任意执行代码的恶意程序。

## 模块

```text
agent-security-core        无第三方依赖的事件、检测器 SPI、策略引擎
agent-security-policy      可独立使用的工具白名单和严格 JSON 参数策略
agent-security-javaagent   Byte Buddy 自动插桩；打包时隔离 Byte Buddy 包名
demo                       仅依赖 LangChain4j 的普通应用 + 独立 JVM 集成测试
integration-spring-boot     Boot 可执行 JAR、应用 SPI、官方 OpenAI 客户端 + 本机 HTTP/SSE 测试
config/demo.properties     可修改的演示策略
config/deployment-example.properties  有界检测与文件审计的部署配置示例
docs/                      调研报告
```

Agent 不包含 LangChain4j 本身，用反射适配应用中的固定版本，避免在 `premain` 提前加载目标类。Byte Buddy 将检查代码插入接口 default 方法、模型实现、工具执行器和 `ToolService` 调度入口。

特别在 `ToolService.executeWithErrorHandling*` 的原方法体之前执行决策，防止普通工具错误处理器将安全拒绝转换为模型可见文本。工具返回检测只能防止返回值继续传播，不能撤销工具已经产生的副作用。

## 策略文件

UTF-8 Java properties：

```properties
deny.tools=sendEmail,deleteAll
deny.text=IGNORE_SECURITY_TEST,DEMO_SECRET_123
max.text.chars=100000
```

- `deny.tools`：工具名精确匹配，区分大小写。
- `allow.tools`：可选的工具白名单；配置后未列出的工具全部拒绝，显式空值表示拒绝所有工具。黑名单优先。
- `allow.retrievers`：可选的检索器实现类白名单；精确匹配检索事件 operation，显式空值拒绝全部检索器；用户权限与数据源 ACL 另行接入。
- `deny.text`：逗号分隔的字面子串，不区分大小写；检查输入／输出文本和原始工具参数字符串。
- `max.text.chars`：检查文本的长度上限（Java UTF-16 长度）；不是网络读取或堆内存配额。
- 未设置白名单／结构化策略且未命中字面规则时放行；空黑名单不提供对应保护。未知配置键、非法上限、文件缺失导致启动失败。
- 配置在启动时加载，修改后需重启；当前没有动态更新。

**字面匹配不是语义提示注入检测器。** 单独使用它不负责 JSON 参数解码；转义、编码、改写可能绕过字面规则。启用下面的结构化工具策略后，会按解码后的 JSON 校验参数，并对其中的键／字符串重新应用本地文本规则；这仍不等于通用域名验证、租户授权、SQL／命令安全。

## 结构化工具权限

在 properties 中设置 `tool.policy.path=tool-policy-example.json`，相对路径以 **properties 所在目录** 为基准。参考 [工具策略示例](config/tool-policy-example.json) 和 [规则说明](docs/tool-policy.md)。

启用后只允许 JSON 文件中列出的工具，并检查实际执行参数的类型、必填项、枚举、数值范围和长度。所有对象默认拒绝未知字段；JSON 重复键（包括转义后同名）、尾随内容、异常深度和畸形 Unicode 都会拒绝。未支持的规则关键字在启动时拒绝，不会悄悄忽略。

示例仅允许 `lookupCustomer(customerId="demo-customer", limit=1..10)` 和无参数的 `readCustomer()`。这个示例是静态部署权限；需要用户／租户约束时，使用下面的可信上下文及对应策略。`allow.tools`、`deny.tools`、结构化策略和插件同时生效，任一拒绝都不能由其他规则覆盖。

结构化策略作为检测器运行，沿用检测链总预算和并发上限；策略文件在启动时加载，修改需重启。单独使用 SDK 时可依赖 `agent-security-policy`，将 `ToolPolicy.fromPath(path)` 放入 `PolicyEngine` 的检测器列表；如需对解码后的字符串应用本地内容规则，使用 `ToolPolicy.fromPath(path, localPolicy)`。

## 可信身份与异步传播

应用依赖同版本 `agent-security-core`，在已完成认证的入口创建上下文：

```java
SecurityContext context = SecurityContext.authenticated(
        authenticatedTenantId, authenticatedUserId, verifiedPermissions);
try (var scope = SecurityContexts.open(context)) {
    return assistant.chat(userMessage);
}
```

`authenticated` 只创建不可变快照，不验证 token 或计算权限；这些值必须来自应用可信的认证／授权结果。启用 `context.required=true` 后，缺少身份的受保护操作拒绝。结构化规则可用 `permissions` 要求工具权限，用字符串规则 `equalsContext` 将参数绑定到 `tenantId` 或 `principalId`，防止模型改写身份参数。

已验证模型 future 完成、回调／Flow 信号、LangChain4j 默认执行器、工具自定义执行器，以及默认 RAG 编排器执行器和组件 future 的传播与线程复用隔离。业务自行创建的异步任务使用 `SecurityContexts.executor` 或 `wrap`；不自动覆盖任意线程池或 Reactor。详见 [完整接入与边界](docs/security-context.md) 和 [身份策略示例](config/context-tool-policy-example.json)。

## 多 Agent 委托

同 JVM 可通过 `AgentRuntime` 显式创建根任务和子任务，按父权限、子 Agent 上限与申请范围取交集，并在受保护操作前检查有效性。支持父子执行关联、异步子任务、撤销／过期及 schema 3 审计；业务认证与根授权由宿主提供，尚无跨服务 Token 或自动父子调用发现。完整示例见 [多 Agent 接入](docs/multi-agent-security.md)。

## 扩展检测器 / 单独使用 SDK

完整接入步骤见 [SDK 扩展指南](docs/sdk-extension.md)：扩展点对照、可复制的策略插件、SPI 注册与自检、普通 Java／Boot 部署、事件字段、自定义审计及排错。

独立使用 `agent-security-core` 时可直接构造 `PolicyEngine`，在副作用发生前调用：

```java
Detector detector = event -> event.operation().equals("deleteAll")
        ? Decision.deny("destructive-tool") : Decision.allow();
PolicyEngine engine = new PolicyEngine(List.of(detector), (event, decision) -> {
    // 记录脱敏决策，避免输出 event.text()
});
engine.check(new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "deleteAll", "{}"));
// 只有 check 成功返回后才执行真实操作
```

Java Agent 在首次使用受保护请求时，通过该请求的应用 ClassLoader 的 `ServiceLoader<Detector>` 加载额外检测器。插件 JAR 放在应用 classpath（包括 Boot nested JAR），并提供：

```text
META-INF/services/io.agentsecurity.core.Detector
```

文件内填写实现类全名。插件需有 public 无参构造器；实现必须线程安全。插件构造和检测在共享的有界线程池中执行，默认检测链总预算 500 ms，最多 4 个执行线程和 4 个排队任务。每个事件使用一个总预算，不为链中每个检测器重置超时；插件构造另有一次相同预算。超时后请求中断；拒绝响应不依赖插件是否接受中断。忽略中断的插件会占用固定线程并使后续操作拒绝，不能强制安全终止其代码。现提供可选 RemoteHttpDetector，包含 HTTP 总预算、并发名额、请求/响应上限和故障拒绝；端点、TLS、认证和内容最小化由可信宿主配置。详见 [远程检测客户端](docs/remote-detector.md)。

```properties
detector.timeout.millis=500
detector.max.concurrent=4
```

检测器应返回短、固定的规则 ID（1～80 位字母、数字、下划线、点或连字符），禁止把业务数据或异常内容放入 ID。独立使用 SDK 时在生命周期结束调用 `PolicyEngine.close()`；Agent 在 JVM 退出时关闭其执行器。

当前同一调用经过多个保护层会触发多次检测。检测器应无副作用，不要用检测调用次数直接扣额度；同一上下文可通过 `runId` 关联，事件去重与 tool-call 关联尚未实现。

## 故障与审计

- 检测器抛出运行时异常或返回 null：拒绝，原因 `detector-error`。
- 检测超时、容量耗尽、调用线程中断、执行器关闭：分别拒绝为 `detector-timeout`、`detector-capacity`、`detector-interrupted`、`detector-closed`。本地字面规则仍在调用线程执行；上述预算不能保证整个业务调用在相同时间内返回。
- 输入／工具执行前拒绝：底层被保护方法不执行。
- 版本检查：受保护入口运行时校验 `langchain4j-core` 的 Maven 元数据，只接受 `1.20.0`；检查不是对任意混用依赖的完整兼容性证明。
- 转换失败：输出 `TRANSFORM_ERROR`，拒绝该类的定义（`ClassFormatError`），后续受保护调用拒绝为 `instrumentation-error`；不直接终止宿主 JVM。JVM 会忽略普通 transformer 异常，因此不能仅抛异常后继续加载原始字节码。应用是否能从类加载失败恢复取决于应用本身，SDK 不承诺维持其可用性。
- 默认审计到 stderr；配置 `audit.path` 后改为 JSONL 文件，记录时间、随机事件 ID、上下文 runId、阶段、ALLOW/DENY、规则 ID、规则版本。内置日志不序列化 prompt、工具参数、结果、用户／租户标识或权限；stderr 不是持久化存储。
- 审计收到写入确认后才释放受保护操作。写入异常、超时、队列满：拒绝为 `audit-error`，该审计实例在重启前持续拒绝。文件写入失败后也停止接受新记录，避免部分写入后继续追加。审计故障本身可能无法写入该文件，应监控业务错误和进程状态。
- `instrumented=...` 表示某个类型已增强，不等于全部业务操作受保护。启动成功也不是全覆盖认证。
- 身份由应用显式提供；当前没有自动认证框架集成、审批流、预算扣减、分布式追踪或生产 SLA。

文件审计配置示例：

```properties
policy.version=example-v1
audit.path=/absolute/private/directory/decisions.jsonl
audit.max.bytes=10485760
audit.backups=5
audit.force=true
audit.timeout.millis=1000
audit.queue.capacity=128
```

单实例独占日志文件；轮转后最多保留当前文件和 5 个备份。新建 POSIX 文件权限为 `0600`；已有目录／文件权限由部署方管理，目录必须受信任。Windows ACL 未实测。不要用外部 logrotate 操作这些文件；多个 JVM 使用不同路径。`audit.force=true` 每条写入调用 `FileChannel.force(true)`，会增加延迟；不提供跨文件轮转的事务性、断电恢复、远程归档或防篡改保证。

审计表示**策略决策**，不表示模型调用或工具副作用已经成功。超时写入可能稍后出现在日志中，原请求仍然拒绝。JSONL `schemaVersion=3` 保留可空 `runId`，并增加 Agent 执行／父执行／委托关联字段；`eventId` 标识一次检测，`runId` 关联同一身份作用域的多个保护层，尚无自动去重。版本拒绝、适配错误、插件加载失败等发生在策略引擎之外的错误，尚未全部进入这个决策日志。具体部署、格式迁移和恢复步骤见 [运行手册](docs/operations.md)。

## 验证方式

带 SBOM、隔离重建比对和 SHA-256 交付清单的流程：`bash scripts/release.sh`，详见 [发布工程](docs/release-engineering.md)。CI 已配置 JDK 17／21，但远端尚未执行；配置不代表支持矩阵已经验收。

本轮完整发布验证运行环境：JDK 21.0.4、LangChain4j 1.20.0、Spring Boot 4.1.1。最新通过数量与验收缺口见 [生产验收清单](docs/production-readiness.md)，原始结果保存在各模块 `target/surefire-reports` 和 `target/failsafe-reports`。

`bash scripts/verify.sh` 执行 `clean verify`：清除旧构建输出，运行 core／Agent 单元测试、打包 Agent 和 demo，再由 Failsafe 为每个集成场景启动新的 JVM。覆盖无 Agent 对照、合法放行、输入／输出拒绝、工具副作用计数、吞异常的业务 handler、工具返回检测、异步路径、并发调度、回调／reactive 流、外部配置和日志不含测试敏感标记。

没有外部模型推理效果或性能数据；官方客户端连接本机端点的测试证明指定边界的工程行为，不证明提示注入检测准确率。

已补远程检测客户端与运行健康指标；已提供 [策略原子发布与回滚](docs/policy-versioning.md)；已补 [MCP 工具边界](docs/mcp-security.md)；已补 [资源/提示词及真实传输验收](docs/mcp-content-security.md)；已补 [发现与响应容量限制](docs/mcp-discovery-limits.md)；已补 [分页预算与容量指标](docs/mcp-pagination-metrics.md)；已补整次分页查询的时间预算；后续推进结构化故障诊断、认证/故障矩阵和发布验收。RAG 与 memory 的接入及未覆盖路径见 [RAG](docs/rag-security.md) 和 [ChatMemory](docs/memory-security.md)。当前仍不能标记为完整生产可用。

## 流式安全模式

回调式流默认全量缓冲，最终输出和实际流片段分别检查，防止 provider 的最终汇总遗漏已输出片段。校验前不释放正文、thinking、完整工具回调。正常通过后按原顺序回放，因此首字延迟变为完整生成与检查所需时间。

```properties
stream.max.chars=100000
stream.max.events=2048
stream.max.active=64
stream.timeout.millis=60000
```

这些限制控制每个保护器持有的字符与事件、活跃保护器数量，以及整个流的截止时间。回调和 reactive 共享活跃流容量。达到上限则拒绝并丢弃缓冲；回调流有可用 `StreamingHandle` 时尝试取消上游，reactive 通过 `Subscription.cancel()` 传播取消。标准接口转发在 provider 边界包装一次；自定义层层包装的模型可能占用多个保护器名额。上游已经分配的内存不属于 SDK 的缓冲上限，最终响应还受模型文本检查上限约束。

未知原始事件拒绝。针对官方 OpenAI Chat Completions SSE，已适配标准无文本控制事件／usage 和 `[DONE]`：严格 JSON 解析、拒绝重复键、限制深度，解码后的字符串也需通过策略检查。非标准 Responses API、任意 provider 自定义事件不在此支持范围内。

Reactive Publisher 保持冷订阅：仅创建 Publisher 不启动模型请求；每次订阅独立缓冲和校验。为完成整段检查，Agent 向上游请求全部事件，依靠字符／事件上限拒绝超量响应；这不是对模型生成速度的端到端限速。校验完成后，向下游发送的事件数不超过 `request(n)`，并保持原顺序。订阅者不请求事件时仍占用容量，直到消费完、取消或超时，不会无限保留。订阅前的输入拒绝作为失败的 Publisher 交付，先 `onSubscribe` 再 `onError`；无效 demand 返回 `IllegalArgumentException`。

固定事件类型包括正文、thinking、工具参数片段、完整工具调用、已知原始控制事件和最终响应。上游必须在一个 `CompleteResponse` 之后结束；缺少最终响应、重复最终响应、最终响应之后继续发送事件均拒绝。未知事件不会未经检查传递。该适配面向模型的 `ChatModelStreamingEvent`；不宣称已直接检查 AI Services 的全部高层事件或任意第三方 Publisher。

超时工作与用户通知使用独立、受并发上限约束的线程池，避免用户回调阻塞唯一计时线程。插件检测和 Agent 审计各有有界执行器和等待期限；策略检查可能阻塞调用线程至这两个预算耗尽，不是全异步调度。Subscriber 必须遵守 Flow 非阻塞回调契约；不能强制中断阻塞的用户代码。测试覆盖并发／重入 request、取消、慢回调及一次终止，但尚未通过独立 Reactive Streams TCK 或长期并发压力验收。

先看 [图解框架原理](docs/architecture-explained.md)，通过整体架构、启动流程、工具放行／阻断、事件和异步图理解各部分的职责。

第一次阅读源码可按 [源码学习指南](docs/source-learning.md) 从一次工具阻断开始，逐步跟踪策略引擎、Agent 插桩、SPI、异步和流式保护。

代码布局、中文注释约定和自动格式检查见 [开发规范](docs/development.md)。

## 文档 Wiki

文档站点名称为 **Agent Security Wiki**，副标题为“Java AI Agent 运行时安全指南”。从 [Wiki 首页](docs/index.md) 按主题浏览，或查看 [Wiki 维护指南](docs/wiki-maintenance.md)了解本地预览和 GitHub Pages 自动发布。

```bash
python3 -m venv .venv-docs
source .venv-docs/bin/activate
python -m pip install -r requirements-docs.txt
mkdocs serve
```

打开 `http://127.0.0.1:8000/`。严格构建使用 `mkdocs build --strict`，输出位于 `site/`。

## 可观测性

提供不依赖 Spring 的固定维度指标、耗时分桶和有界父子执行关联队列。Java Agent 可设置 `telemetry.enabled=true`，业务通过 `SecurityTelemetry.global()` 拉取；独立 SDK 可显式传入收集器。默认关闭，队列满不影响安全决策。可选 `agent-security-telemetry` 模块提供 Prometheus 文本及 OTLP/HTTP 日志导出，不要求 Spring。接入、限制和后续路线见 [可观测性指南](docs/observability.md)。
