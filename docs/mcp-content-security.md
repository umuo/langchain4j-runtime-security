# MCP 资源、提示词与真实传输验收

在 [MCP 工具边界](mcp-security.md) 基础上，本迭代增加资源读取和提示词渲染的独立输入/输出检测。固定版本仍为 LangChain4j core 1.20.0、MCP 1.20.0-beta30，无需 Spring。

## 1. 支持哪些调用

| 客户端入口 | 输入检测 | 返回检测 |
| --- | --- | --- |
| readResource(String) | 服务 + 原始 URI 精确授权，URI 内容规则 | 每项 URI、MIME 类型和文本，URI 必须与请求完全一致 |
| readResource(String, InvocationContext) | 同上 | 同上 |
| getPrompt(String, Map) | 服务 + 名称精确授权，参数键和值的文本规则 | 描述、每条消息角色和文本 |

这几个固定版本入口均为同步 API。MCP 工具的同步与异步 API 继续由已有适配保护。返回整批检查通过后才交付；捕获入口 SecurityContext，输出检测仍采用原调用者身份。

新阶段为 `MCP_RESOURCE_INPUT`、`MCP_RESOURCE_OUTPUT`、`MCP_PROMPT_INPUT`、`MCP_PROMPT_OUTPUT`。自定义 Detector、远程检测 phases、审计消费端的枚举解析需要同步配置。正常引擎检查继续强制审计，检测异常仍拒绝操作。

## 2. 为业务生成精确授权

提供不依赖 LangChain4j 的 SDK 工具类 `io.agentsecurity.core.mcp.McpOperations`：

```java
String resource = McpOperations.resource("inventory", "docs://inventory/item-1");
String prompt = McpOperations.prompt("inventory", "summarize");

Properties policy = new Properties();
policy.setProperty("allow.mcp.resources", resource);
policy.setProperty("allow.mcp.prompts", prompt);
policy.setProperty("deny.text", "secret-marker");

// 由宿主部署流程写入 Agent 启动时读取的 UTF-8 properties 文件。
try (var writer = Files.newBufferedWriter(Path.of("policy.properties"))) {
    policy.store(writer, "Dedicated MCP policy");
}
```

然后按已有 `-javaagent:...=/absolute/path/policy.properties` 启动。SDK 模式可以直接 `new LocalPolicy(policy)` 并将其加入 PolicyEngine；自动拦截仍需 Java Agent。业务 SDK 构建文件需引用 `agent-security-core`。

名称格式如下：

| 配置 | 授权名格式 | 默认 |
| --- | --- | --- |
| allow.mcp.resources | mcp-resource:服务/SHA256(原始URI) | 全部拒绝 |
| allow.mcp.prompts | mcp-prompt:服务/提示词名 | 全部拒绝 |

多个授权使用逗号分隔，不支持通配符或前缀匹配。三个 MCP 允许列表各自独立，`allow.mcp.tools` 不会开放资源或提示词。

资源 URI 必须是绝对 URI，最多 1024 个可打印 ASCII 字符，不接受空白；Unicode 需要由宿主先转换为百分号编码 URI，再将同一字符串用于授权与调用。不做解码、大小写折叠或路径归一化：`docs://a/one` 与 `docs://a/%6fne` 是不同授权。摘要用于限制授权名长度，既不是认证机制，也不是 URI 脱敏保证。

服务 key/提示词名只接受 1～100 个字母、数字、下划线、点、连字符。服务 key 仍由受信任宿主唯一绑定 endpoint/进程，不接受模型选择的任意服务身份。

## 3. 多 Agent 权限及业务扩展

当前 AgentGrant 的 `tools` 集合承载 MCP 操作能力，可加入上述完整授权名：

```java
AgentGrant grant = AgentGrant.tools(
        Set.of("read"),
        Set.of(
                McpOperations.resource("inventory", "docs://inventory/item-1"),
                McpOperations.prompt("inventory", "summarize")));
```

父子授权仍取交集。只授权普通 `lookup` 或工具 `mcp:inventory/lookup`，不能调用该资源和提示词；换服务器、URI、提示词名称也不会继承许可。已关闭、过期、撤销的 Agent 按原生命周期规则拒绝。

资源事件包含 `ResourceRef("mcp-resource", 原始URI)`，检测器可结合 `event.operation()` 中的服务和 `event.context()` 中的可信租户查询业务 ACL。URI 不是归属证明，允许列表也不会代替服务端资源鉴权。提示词参数当前作为有界文本交给 Detector，不套用 ToolPolicy 的工具 JSON schema；需要字段级权限的业务应单独实现策略，不能把拼接后的文本当作可逆参数协议。

可复用 SPI、远程检测、版本发布。示意：

```java
if (event.phase() == SecurityEvent.Phase.MCP_RESOURCE_INPUT) {
    // event.resource().id() 是内存中的原始 URI；不要写入无保护日志。
    return aclAllows(event.context(), event.operation(), event.resource())
            ? Decision.allow() : Decision.deny("business-resource-denied");
}
return Decision.allow();
```

这里 `aclAllows` 是宿主实现的授权函数，不是 SDK 提供的默认授权。

## 4. 有界返回处理

- 资源最多 128 项，逐项要求文本类型且 URI 与请求原样一致。二进制资源拒绝；链接指向其他 URI 时也拒绝，需要宿主另行授权访问。
- 提示词最多 128 条消息，仅支持 USER/ASSISTANT 的文本内容。图片、音频、嵌入资源和未知类型拒绝。
- 提示词参数最多 64 个字符串键值；null 参数 Map 表示无参数，非字符串值拒绝。
- URI、MIME、描述、角色、正文、参数的拼接结果受已有 `max.text.chars` 限制。此限制作用于客户端解析后的数据，不是传输层响应字节上限。

| ruleId | 含义 |
| --- | --- |
| mcp-resource-not-allowed / mcp-prompt-not-allowed | 完整操作不在对应允许列表 |
| invalid-mcp-target | URI 或提示词名称无效 |
| mcp-resource-uri-mismatch | 返回了其他资源 URI |
| unsupported-mcp-content | 二进制、非文本、未知或空的返回对象 |
| mcp-content-limit | 内容条数超限或集合形状错误 |
| mcp-prompt-arguments | 参数不是 Map 或数量超限 |
| adapter-shape-error | 参数键值或文本字段不是字符串 |
| agent-tool-denied | 当前 Agent 未获此 MCP 操作能力 |
| denied-text / text-limit | 文本规则拒绝 |

与既有适配相同，形状、版本和容量等引擎外拒绝尚未全部进入策略审计；不能把审计事件数量作为完整拦截计数。客户端解析器丢弃的未知字段、原始响应监听器、转换器、日志和异常消息仍不属于本文本边界。

## 5. 真实传输怎么验收

`demo/src/test/java/io/agentsecurity/demo/McpTransportIT.java` 在独立 JVM 加载已打包 Java Agent，使用官方 DefaultMcpClient 与官方传输实现，固定 MCP 协议 `2025-11-25`：

| 模式 | 实际链路 |
| --- | --- |
| http | 本机 HTTP POST，服务端返回 application/json |
| sse | 本机 HTTP POST，服务端返回 text/event-stream 的 message 事件 |
| stdio | 官方 StdioMcpTransport 启动独立 Java MCP 服务端，经 stdin/stdout 交换 JSON-RPC |

同一协议夹具用于三种传输，每个场景保存服务端业务请求日志，排除初始化和通知。允许调用恰好一次；输入授权/委托/参数内容拒绝为零次；恶意输出、错误 URI、二进制或条数超限在一次调用后拒绝交付。还回归异步工具的允许、默认拒绝和输出拒绝。

执行 `bash scripts/release.sh`，使用仓库支持的 JDK/Maven 环境。单场景子 JVM 超时 30 秒会终止自身及子进程；服务端只监听随机 loopback 端口，测试不访问外部 MCP 服务。

本地服务端是协议夹具，不是第三方服务器互操作证明。SSE 仅验收 POST 响应事件流，不包括旧版独立 SSE endpoint、长期通知、断线恢复或订阅。尚未验收 MCP 协议 `2026-07-28`、MCP TLS/OAuth、外部服务端、网络故障重试和原始响应内存上限；既有 Collector TLS 测试不能代替 MCP TLS 测试。

## 6. 仍未覆盖

发现列表与 instructions 已在 [后续迭代](mcp-discovery-limits.md) 适配，并加入官方传输响应字节限制。订阅、初始化权限、roots、子进程启动权限和直接调用底层 transport 的策略授权仍未覆盖。构造客户端会初始化网络或进程，所以零业务请求不代表零连接。

发现与容量基础已补，分页预算与容量指标已在 [后续迭代](mcp-pagination-metrics.md) 加入；下一阶段继续补总截止时间、认证、重连和超时故障矩阵。已经返回输出拒绝时，服务端操作不会被回滚。
