# MCP HTTP 认证与连接故障治理

固定支持 LangChain4j core 1.20.0 / MCP 1.20.0-beta30 的官方 StreamableHttpMcpTransport，覆盖 HTTP JSON 与 POST 响应 SSE。防护位于独立 Java Agent，不依赖 Spring。

## 1. 接入：宿主提供凭据，Agent 检查传输

在现有 Agent properties 中配置：

```properties
# 默认 false；设为 true 时，每个 HTTP 请求必须带一个合法形式的 Bearer 头。
mcp.http.require.bearer=true
allow.mcp.discovery=mcp-discovery:inventory/listTools
allow.mcp.tools=mcp:inventory/lookup
```

宿主使用官方客户端的 customHeaders 提供凭据。下面只展示读取入口；secretStore 是宿主已有的可信凭据存储。

```java
var transport = new StreamableHttpMcpTransport.Builder()
        .url("https://mcp.example.com/mcp")
        .customHeaders(() -> Map.of("Authorization", "Bearer " + secretStore.accessToken()))
        .followRedirects(false)
        .timeout(Duration.ofSeconds(10))
        .build();

var client = DefaultMcpClient.builder()
        .key("inventory")
        .transport(transport)
        .toolExecutionTimeout(Duration.ofSeconds(5))
        .resourcesTimeout(Duration.ofSeconds(5))
        .promptsTimeout(Duration.ofSeconds(5))
        .build();
```

配置只接受 true/false，不随动态策略发布更新；每个传输构造时固定是否要求 Bearer。false 允许匿名 HTTP 请求；如果发送 Authorization，也会绑定其值。true 要求恰好一个 Authorization，Bearer scheme 不区分大小写，token 必须非空、符合已支持的 ASCII 形式，整个头最多 8192 字符。这里不验证 token 签名、有效期、受众或权限，验证由服务器完成。401/403 会使传输失效。

每个传输在第一次实际请求时绑定 Authorization 的 SHA-256 指纹，包括“无头”状态；匿名状态和有头状态使用不同前缀。凭据变化后，在发出新请求前拒绝。Agent 不长期保存 token 原文，不刷新 token；宿主应在刷新后关闭旧客户端，使用新凭据构造新传输和客户端。凭据包含可变化的签名/时间字段时也会触发此检查。

首次握手与初始化通知也受检查。建议宿主先准备好当前凭据，再创建客户端。已有认证失败不能通过修改 headers supplier 原地恢复。

## 2. 固定目标，防止凭据随重定向转发

官方传输构造时绑定配置 URL；HTTP 请求的 URI 必须与其相等，包括路径及 query。拒绝 userinfo、fragment、不支持的 scheme、没有 host 的地址。

远程地址必须是 HTTPS。只允许字面量 `http://127.0.0.1` 或 `http://[::1]` 用于本机验收；不把 localhost 或其他 DNS 名称当作 loopback 例外。HTTPS 的证书信任和 hostname 校验仍使用宿主/JDK HTTP 客户端配置，本轮未增加独立 CA、证书 pinning 或 mTLS 凭据管理。

设置 followRedirects(true) 会在传输构造时拒绝。即使服务器返回同源重定向，也会按失败处理，不访问 Location。不要为了接入而在生产服务器返回 301/302/307/308；直接配置最终 HTTPS MCP 地址。

升级影响：这些目标/重定向检查默认开启，过去使用远程 HTTP 或自动重定向的官方传输需要调整。Bearer 必填默认关闭，可按上述配置开启。此规则不形成域名 allowlist，也不防止宿主将可信 token 配置给错误的初始 HTTPS 地址；目标配置必须来自可信宿主。

## 3. 失败后如何恢复

| ruleId | 触发条件 | 处理方式 |
| --- | --- | --- |
| mcp-http-target | URL 不可接受，或请求 URI 与绑定 URL 不一致 | 修正目标配置，重新创建传输 |
| mcp-http-redirect-config | HTTP 客户端启用了自动重定向 | 使用最终地址，关闭自动重定向 |
| mcp-http-auth-required | 必填 Bearer 缺失、格式不符、重复 Authorization 或头超长 | 修正凭据来源，重建客户端 |
| mcp-http-credential-changed | 同一传输的 Authorization 指纹变化 | 关闭旧客户端，用新凭据重建 |
| mcp-http-auth-failed | HTTP 401/403 | 检查凭据及服务端权限，取得有效凭据后重建 |
| mcp-http-session-expired | HTTP 404 | 核对 endpoint/会话，显式重建；404 并不证明一定是会话过期 |
| mcp-http-redirect | HTTP 3xx | 修正为最终地址后重建 |
| mcp-http-unavailable | HTTP 5xx | 服务恢复后，由宿主决定何时重建 |
| mcp-http-transport-failed | 异步 HTTP 请求失败，包括响应正文中途断开 | 排查连接/超时，显式重建 |

以上请求/响应故障保持该传输失效；共享传输的多个客户端也共享失效状态。后续 MCP 入口先检查状态，包含目录缓存命中，阻止失败客户端返回旧缓存作为成功结果。首个失效原因保留；同一传输的后续错误不会覆盖它。构造时配置拒绝发生在客户端可用之前。

HTTP 401/403、404、3xx、5xx 在响应头阶段拒绝，不解析或记录错误正文。404 在官方旧协议的隐式 reinitialize 分支之前被拒绝，因此不会偷偷重新握手再重放原操作。本轮没有 Agent 自动重试/自动重连；底层 JDK 的连接建立细节仍由其实现决定，不能据此保证所有网络层尝试都只有一次。

异步网络失败先标记失效再交付阻断异常；包装层 HTTP Future 的取消向 JDK 发送 Future 传播；官方 MCP 返回的是另一层 Future，取消 MCP 调用不保证立即取消底层 HTTP 请求。显式关闭仍沿用上一轮 shutdownNow/close 处理在途请求。取消、超时或关闭不保证服务端回滚已经发生的工具副作用，重建后是否重试写操作必须由宿主按业务幂等性决定。

## 4. 与 Agent 身份及权限的关系

这是一条传输凭据边界。SecurityContext/AgentRuntime 仍负责调用者身份、父子关系与工具授权；Bearer 头不能替代委托权限。customHeaders 可读取宿主已验证的凭据，但不能从模型文本或工具参数拼出可信身份。

同一传输固定凭据，适合服务身份。不同用户/租户需要不同服务器凭据时，应由可信宿主按身份分配独立客户端/传输和缓存。仍使用相同 Bearer 的不同调用者，不会因为本功能自动获得服务端的用户隔离；SDK 的调用者权限检查需要继续正确接入。

缓存命中不发送 HTTP 请求，不能发现 headers supplier 已变化或服务器已撤销 token。宿主必须在凭据刷新、身份切换或撤销时主动关闭/重建；本功能不提供每次缓存读取的远端认证证明。

本轮不提供 OAuth 握手、发现、token endpoint、刷新、过期时间本地校验或跨服务签名委托。只检查 Authorization，不将任意自定义 API-key 头、cookie、代理凭据或 token 放在 query 的方案纳入认证绑定。stdio 没有 HTTP 头，本配置不对 stdio 子进程提供身份验证或沙箱。

## 5. 故障诊断与指标

新增固定分类 AUTHENTICATION_FAILURE、SESSION_FAILURE、DESTINATION_FAILURE。HTTP 不可用/连接故障使用 TRANSPORT_FAILURE；HTTP 级记录使用 MCP_EXECUTION，捕获请求发出时的 SecurityContext。握手和内部后台请求可能没有上下文，事件/版本/操作边界信息可为空或 UNKNOWN，不伪造业务检测事件。

规则与版本仍使用指纹，队列/JSON 不输出 token、URL、响应错误文本。HTTP 传输级拒绝进入诊断通道，不自动生成强制审计事件；业务入口/出口通过 PolicyEngine 产生的审计继续保留。使用 [结构化故障诊断](failure-diagnostics.md) 的 JSON/Prometheus 接口获取记录。

`agent_security_mcp_transport_failures_total` 仍只计容量导致的故障，不把认证错误混入容量拒绝。`failed_state_checks_total` 包含对已失效状态的检查；认证/目标/会话/连接原因看 `agent_security_failures_total` 的固定类别及规则指纹。故障次数不等同于任务数或网络请求数。

## 6. 如何验收

`McpHttpSecurityTest` 覆盖目标与 loopback 规则、重定向配置、严格 Bearer 配置、头格式/大小/重复、匿名与有凭据状态区分、凭据变化、HTTP 状态失效、后续状态检查及容量计数不混入认证故障。

McpTransportIT 的真实 HTTP/SSE 增加：正常 Bearer、401/403/404/503、307、业务请求前缺失/格式错误/凭据变化，以及响应正文中途断开。每个失败场景再调用同一客户端，验证入口拒绝、业务请求不增加；404 验证只握手一次，307 验证重定向目标请求数为零；原有安全、分页和关闭矩阵继续回归。

完整运行 `bash scripts/release.sh`，实际数量、环境及产物验证见 [生产验收记录](production-readiness.md)。认证验收使用本机 HTTP 服务，不等价于外部 OAuth 服务或生产 HTTPS/mTLS 验收。下一项按计划推进多 Agent 共享预算与任务树取消。
