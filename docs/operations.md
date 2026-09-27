# 运行、错误处理与恢复

本文适用于当前固定 LangChain4j 1.20.0 的构建。完整生产验收仍未完成，见 [进度](production-readiness.md)。故障策略固定为拒绝受保护操作，不提供自动 fail-open 开关。

## 安装与启动

1. 使用 JDK 21 和 Maven 执行 `bash scripts/verify.sh`；确认所有模块成功。
2. 将 `agent-security-javaagent/target/agent-security-javaagent.jar` 和经审核的策略文件作为一组部署。策略示例为 `config/deployment-example.properties`，其中字面规则仅用于演示。
3. 为每个 JVM 分配独立、受信任、服务账号可写的审计目录。将 `audit.path` 改成绝对路径。已有目录和文件应限制为服务账号及授权运维可访问；不要放在多人可写目录或与其他进程共享日志。
4. 在所有可能提前加载 LangChain4j 的其他 Agent 之前加入 `-javaagent:/opt/agent-security/agent-security-javaagent.jar=/etc/agent-security/policy.properties`，然后启动应用。
5. 使用本应用的无副作用健康检查分别验证合法放行、模型输入拒绝和工具执行前拒绝，确认真实工具调用次数为零。检查 JSONL 中的 `policyVersion`。仅看到 `installed`／`instrumented` 日志不构成覆盖证明。

插件检测器放在应用 classpath 或 Boot 的 nested JAR 内，提供 `META-INF/services/io.agentsecurity.core.Detector`。插件必须线程安全、无副作用；身份优先读取 `event.context()` 的不可变快照。检测工作线程会安装同一 SDK 上下文，但不会复制应用任意 ThreadLocal。应用认证入口的配置见 [可信上下文](security-context.md)。

同一调用可能经过多个保护层，触发多次检测、审计和等待。评估延迟时计入实际保护层数量，不能把 `detector.timeout.millis` 当成整个 HTTP 请求的超时。插件自身的网络访问还需连接／读取超时、响应大小限制和连接池配额。

## 错误契约

SDK 抛出 `SecurityBlockedException`，`ruleId()` 是稳定原因标识。异步入口通常以失败的 `CompletableFuture` 交付；回调流通过 `onError` 交付输出拒绝，输入拒绝可能同步抛出。Reactive 输入／输出拒绝在订阅后通过 `onError` 交付，并先发送 `onSubscribe`。调用方应根据失败类型停止本次操作，不要把拒绝转换为默认成功结果。业务接口到 HTTP 状态码的映射由应用定义，不要解析异常 message 判定权限。

| 原因 | 含义 | 处理 |
| --- | --- | --- |
| `denied-tool` / `denied-text` / 插件规则 ID | 策略拒绝 | 展示可识别错误；依据业务流程复核策略或输入，不自动重试 |
| `tool-not-allowed` | 未在工具白名单／结构化策略文件中列出 | 审核需要开放的工具，更新策略并重启；不从模型声明自动授权 |
| `tool-argument-policy` / `invalid-tool-arguments` / `tool-arguments-limit` | 参数不合规、JSON 不合法或超过大小限制 | 拒绝执行；检查工具参数与策略，保持错误脱敏 |
| `missing-security-context` | 开启全局身份要求，或工具规则需要身份，但事件没有上下文 | 检查认证入口与异步传播；不要从模型参数补造身份 |
| `permission-denied` | 身份缺少工具要求的权限 | 由应用授权系统复核，不根据模型请求自动增加权限 |
| `retriever-not-allowed` | 检索组件未在 `allow.retrievers` 白名单中 | 审核实现类与包装层，不从模型／文档声明自动开放 |
| `memory-message-limit` / `memory-id-limit` / `unsupported-memory-id` | Memory 批次数量、ID 长度或类型超出支持范围 | 检查 [Memory 配置](memory-security.md) 与 ID 适配；不要为绕过拒绝而截断 ID |
| `rag-content-limit` / `unsupported-rag-metadata` | RAG 内容数量／元数据条目超限或元数据类型未支持 | 检查实际检索数据与 [RAG 配置](rag-security.md)，拒绝整个结果批次 |
| `security-context-mismatch` | 在另一身份／run 下订阅已经绑定上下文的 Publisher | 在对应请求作用域内创建独立 Publisher；不要跨请求缓存复用 |
| `detector-timeout` | 检测链或插件初始化超过预算 | 检查检测服务延迟；本次拒绝；后续请求在容量释放后可恢复 |
| `detector-capacity` | 固定检测线程和队列均满 | 检查饱和与忽略中断的插件；不要盲目扩大线程数 |
| `detector-error` / `detector-load-error` | 插件执行、返回值或加载失败 | 检查插件版本和自身脱敏日志；原异常内容不会转发给业务 |
| `detector-interrupted` / `detector-closed` | 调用中断或执行器关闭 | 停止请求，核查生命周期／取消行为 |
| `audit-error` | 审计写入失败、等待超时、容量耗尽或实例已关闭 | Agent 审计持续拒绝直到重启；先修复存储／权限／压力问题 |
| `instrumentation-error` | 类增强失败 | 停止引流，检查 Agent 顺序与支持矩阵；失败类拒绝定义 |
| `unsupported-langchain4j-version` / `missing-version-metadata` | 版本不在支持范围或缺少元数据 | 固定受支持依赖，保留版本元数据；不要关闭检查掩盖不兼容 |
| `unsupported-stream-event` / `unsupported-content` | 事件或内容未支持 | 使用已验证路径；需要新增适配和验证才能放开 |
| `stream-buffer-limit` / `stream-capacity` | 流缓冲或共享活跃流数量达到上限 | 限制生成长度、检查消费者是否及时消费／取消，依据实测调整容量 |
| `stream-timeout` | 生成、检查或消费等待超过流截止时间 | 检查模型延迟和订阅者 demand；丢弃尚未交付的缓冲内容，取消上游 |
| `stream-event-order` / `missing-stream-response` / `stream-protocol-error` | reactive 上游违反已适配事件／订阅协议 | 检查 provider 与版本，不要忽略错误后释放缓存 |

错误响应、告警由业务接入；已有可选进程内指标和有界关联记录收集，见 [可观测性](observability.md)。可选 telemetry 模块提供 Prometheus 文本渲染和 OTLP/HTTP JSON 日志导出；HTTP 指标端点由宿主提供，当前无 JMX 导出。适配、类加载、插件构造等部分错误发生在决策引擎之外，未必存在相应 JSONL 决策记录。

## 审计语义和故障恢复

日志逐条 JSONL，当前 `schemaVersion=3`，包含 UTC 时间、随机 `eventId`、可空 `runId`、阶段、决策、规则 ID、策略版本。`runId` 来自 SDK 上下文，未接入身份时为 null；同一上下文的保护层共享 runId，各次检测仍有独立 eventId。重复保护层不会自动合并。内置实现不写入事件内容、工具名、用户／租户标识或权限；插件必须返回固定规则 ID，不能将敏感数据编码进 ID。

升级前更新日志消费者以同时接受历史 schema 1（没有 runId）、schema 2（runId 可空）与 schema 3（新增委托字段）；保留历史记录，不把缺失字段推断为用户身份。SDK 与 Agent 应使用同一构建版本，应用及插件重新编译验证；当前 SNAPSHOT 不承诺二进制兼容。

RAG 新增 `RETRIEVAL_INPUT`、`RETRIEVAL_OUTPUT`、`AUGMENTATION_INPUT`、`AUGMENTATION_OUTPUT` 四个 phase。日志消费者和插件需接受这些值；当前消息结构为 schema 3。检索器／增强器包装可能产生重复检测，不用事件数量推断实际数据库读取数。

Memory 新增 `MEMORY_READ_INPUT`、`MEMORY_READ_OUTPUT`、`MEMORY_WRITE`、`MEMORY_DELETE`。写入／删除事件在执行前记录，不代表存储操作成功。memory ID 仅通过事件 `resource()` 供插件授权，内置审计不写入该字段；不能从日志缺少 ID 推断已实施逐会话 ACL。

受保护操作在写入确认后才能继续。单写线程与有界队列限制内存；默认等待至多 1000 ms。超时或任何写入故障后，实例在重启前持续拒绝，避免磁盘问题下继续执行未审计操作。发生超时的写入可能稍后完成，因此 ALLOW 仅表示检测决策，不是操作执行成功的凭据。

`audit.force=true` 默认每条记录调用文件强制写入。磁盘／文件系统仍可能故障；当前没有事务性轮转、断电恢复、防篡改链、WORM 存储或远程复制。轮转控制当前配置下新增日志的规模；修改保留数量后，旧配置留下的额外备份需另行管理。不要通过删除日志或自动重启循环来规避故障。

出现 `audit-error` 时，先停止向该实例分配新工作，检查空间、配额、挂载延迟、权限及备份路径冲突；保留现有日志作为故障证据。修复后检查最后一条记录是否完整，如需隔离损坏文件，应在进程退出后将整组文件归档至受控目录。启动新实例并完成放行／拒绝探针，确认审计恢复，再重新引流。插件忽略中断且耗尽固定工作线程时，先修复插件，再重启实例释放资源。

## 更新与回退

策略在启动时加载。更新时为规则集分配新的 `policy.version`，配合固定 Agent JAR 和依赖版本进行灰度；保留上一组已经验证的 Agent 与配置作为回退单元。回退也必须保留安全 Agent，不能通过移除 `-javaagent` 获得表面上的恢复成功。当前不支持远程热更新、动态 attach 或无需重启的卸载。

如果停止进程时仍有工具正在执行，SDK 不能撤销已产生的外部副作用。流式模式在校验前缓冲内容，会增加首字延迟；不适用于要求未经检查的 token 立即展示的产品行为。


## 多 Agent 审计 schema 3

当前 FileAuditSink 输出 schema 3，在 runId 之外增加 agentId、invocationId、parentInvocationId、delegationId；普通请求为 null。原 schema 1／2 日志仍需保留兼容处理。任务生命周期增加 AGENT_START、AGENT_DELEGATE、AGENT_FINISH、AGENT_REVOKE，runtime 生命周期与 Agent 决策日志应分别写入文件并关联查询。完整迁移及生命周期语义见 [多 Agent 安全](multi-agent-security.md)。
