# MCP 发现权限与响应容量限制

本迭代保护发现结果进入应用/模型前的边界，并为固定版本官方 HTTP/SSE、stdio 传输增加解析前的容量限制。支持范围仍是 LangChain4j core `1.20.0` 与 MCP `1.20.0-beta30`。

## 1. 发现权限独立配置

新增配置：

```properties
allow.mcp.discovery=mcp-discovery:inventory/listTools,mcp-discovery:inventory/instructions
mcp.max.response.bytes=1048576
```

`allow.mcp.discovery` 缺省/空值全部拒绝，逗号分隔，不能使用通配符。可选操作如下：

| 操作 | 检查内容 |
| --- | --- |
| listTools | 工具名称、描述、参数 schema 中的字符串 |
| listResources | 名称、描述、URI、MIME 类型 |
| listResourceTemplates | 名称、描述、URI 模板、MIME 类型 |
| listPrompts | 名称、描述、参数名称和描述 |
| instructions | 初始化结果中保存的服务器说明；无说明时按空文本检测 |

支持固定版本的无参和 InvocationContext 重载。每次调用前检查权限，返回后检查整批内容；命中本地缓存也照常检查，不沿用缓存创建者的身份。`instructions()` 是已缓存的初始化信息，输入拒绝不撤销已经发生的初始化请求。

提供公共生成方法：

```java
String capability = McpOperations.discovery("inventory", "listTools");
AgentGrant grant = AgentGrant.tools(Set.of(), Set.of(capability));
```

委托 Agent 必须同时满足 grant 和本地策略。列表权限不会赋予执行、资源读取、提示词渲染权限，也不会过滤列表中未获执行权的项目：允许的是读取整个目录；目录内任一内容拒绝时整批拒绝。

新增 `MCP_DISCOVERY_INPUT` / `MCP_DISCOVERY_OUTPUT` 阶段，operation 为上述完整授权名。自定义 Detector、远程检测 phases 和审计消费端需要同步更新。输入 text 为空，输出 text 为有界汇总文本，不是可逆结构化协议。按字段/资源做授权应使用已有执行、资源和提示词边界，或另行实现类型化发现策略。

## 2. 输出边界

返回列表最多 128 项；提示词参数列表也有 128 项上限。工具 schema 遍历最多 16 层、每个工具最多 1024 个 schema 节点，每个属性/定义集合最多 128 项。支持固定版本的 object、array、anyOf、reference、enum、string、integer、number、boolean、null；未知类型拒绝。检查描述、属性名、required、枚举值、引用等字符串，不调用任意对象的 toString。

汇总内容同时受 `max.text.chars` 限制。工具 metadata、其他目录项 metadata/icons 非空时拒绝；不允许隐藏内容未经检测流出。客户端在解析时丢弃的字段不属于此返回对象检测范围，文本匹配也不是语义注入识别。

规则标识：

| ruleId | 含义 |
| --- | --- |
| mcp-discovery-not-allowed | 未授权此服务的此发现操作 |
| agent-tool-denied | 当前 Agent 没有完整发现授权名 |
| mcp-content-limit | 返回列表或参数列表超限/形状错误 |
| mcp-schema-limit | schema 深度、节点或属性数超限 |
| mcp-discovery-metadata-unsupported | 带非空元数据或图标 |
| unsupported-mcp-content / adapter-shape-error | 未适配的返回类型/字段 |
| denied-text / text-limit | 文本检测拒绝 |

与已有适配一致，引擎外形状/容量拒绝尚未全部进入策略审计；不能把审计记录当作完整容量告警数据。

## 3. 原始响应容量限制如何生效

`mcp.max.response.bytes` 是 Java Agent 启动配置，默认 1 MiB，可配置范围 1024～16777216。不能将此属性直接传给 LocalPolicy/PolicyCompiler，它控制传输适配而非策略版本内容。没有“不限大小”选项。

### HTTP 与 SSE

仅包装官方 StreamableHttpMcpTransport 内部拥有的 JDK HttpClient，不影响应用其他 HTTP 请求。通过 BodySubscriber 在数据交给字符串/SSE 行聚合器之前统计 ByteBuffer 剩余字节。总数超过上限时取消订阅、使响应失败，并标记该传输不可用。

预算是**每个 HTTP 响应体的总字节数**，包括 SSE 的 event/data 行和分隔符，不是每个 SSE 事件。覆盖初始化、正常响应和错误响应；不依赖 Content-Length 声明。网络/JDK 仍会分配接收缓冲块，这不是整个 JVM 内存配额或硬实时内存证明。

SSE 可能在响应体结束前交付一个完整协议结果；之后超限不能撤回已经交付的先前结果。长时间通知流会累积到上限，本轮未宣称支持无限通知、订阅或重连。

### stdio

只在官方 StdioMcpTransport 创建 JsonRpcIoHandler 时包装 stdout 输入流，在 InputStreamReader/BufferedReader 组装完整行之前按原始字节计数。CR/LF 重置计数；超限行被关闭和拒绝，不按字符数量计算，因此多字节 UTF-8 不会绕过上限。

本层关闭的是读取流，不自动杀死业务子进程。框架中已经等待的请求可能直到配置的工具/资源/提示词超时才结束；宿主应设置有限的 `toolExecutionTimeout`、`resourcesTimeout` 和 `promptsTimeout`，并关闭故障客户端。工具超时可能被框架转换为正常结果，因此 Java Agent 在出口再次检查容量故障，阻止这个结果被当作允许结果交付。

### 超限之后

HTTP 和 stdio 容量超限标识为 `mcp-response-limit`。同一传输关联的客户端保持不可用，后续受保护操作在入口被拒绝；重试/重新连接不会清除这个标记。需要宿主重新构造传输及客户端，再走认证与初始化。传输异常在框架包装后可能表现为其他传输/超时异常；以失败交付，不能只靠最外层异常类型判断原因。

容量状态绑定仅对固定版本 DefaultMcpClient 及官方两种传输验收；自定义客户端/传输没有自动获得相同保证。弱引用注册表不持有客户端/传输对象，容量状态不会把一个客户端的故障扩散到无关客户端。

## 4. 升级接入检查

原先允许工具执行的应用可能由 McpToolProvider 自动先调用 listTools 或 instructions，升级后需要显式授予这两个发现权限。应按业务盘点后配置，不要为了恢复调用而开放所有发现权限。

既有配置继续分别负责：

- `allow.mcp.tools`：实际工具执行。
- `allow.mcp.resources`：精确 URI 读取。
- `allow.mcp.prompts`：提示词渲染。
- `allow.mcp.discovery`：目录和 instructions 访问。

资源/提示词配置见 [上一轮接入指南](mcp-content-security.md)，工具配置见 [MCP 工具安全](mcp-security.md)。发现与其他操作仍使用宿主固定的服务 key，不是服务器密码学身份；TLS、OAuth、endpoint 绑定和子进程权限由宿主负责。

## 5. 如何验收

`McpTransportIT` 使用真实 loopback HTTP JSON、POST 响应 SSE、stdio 子进程。新增场景覆盖五类发现操作的允许/默认拒绝、恶意 instructions、工具参数描述、提示词参数描述、隐藏元数据、条数超限、缓存创建后换成无权限 Agent 调用，以及响应超限后再次调用必须拒绝。

业务请求计数来自服务端日志。默认拒绝发现列表时为零；缓存调用不增加请求，仍应拒绝无权限 Agent；instructions 不产生新的业务请求。响应超限场景只发送一次工具调用，后续调用不得再次发给服务端。

`McpResponseLimitsTest` 在字节级验证分块累加、精确边界、取消、CR/LF 重置、无终止符多字节行、单字节读取、故障状态隔离、启动配置检查。使用 `bash scripts/release.sh` 执行完整发布验收。

尚未验收大规模并发、长时间订阅、认证、重连、MCP 2026-07-28 协议、stderr 容量、进程级资源限制和解析器 CPU/深度拒绝。目录分页累计预算及容量指标已在 [后续迭代](mcp-pagination-metrics.md) 加入；单页类型化解析仍会分配页面对象，再检查累计条目。内部监听器/日志仍可能先看到原始响应，响应限流不等于日志内容脱敏。

## 6. 冷启动验证记录

首次 117 个传输场景有 1 个在初始化时触发插桩失败，按故障拒绝策略未发出业务请求；原日志没有异常类型，不能据此确定根因。现把原本已忽略的 JDK/SDK/Byte Buddy 类在转换器入口提前排除，并补充目标类名与异常类型诊断（不打印业务内容），同时增加 20 次独立 JVM 冷启动回归。目标业务类发生插桩错误时仍拒绝加载。该改进不等于证明原始偶发错误的根因已完全消除；部署后应继续观察 instrumentation-error/覆盖健康状态。
