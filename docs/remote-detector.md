# 远程安全检测客户端

`agent-security-policy` 新增 `io.agentsecurity.policy.remote.RemoteHttpDetector`，实现既有 Detector 接口。普通 Java 可直接加入 PolicyEngine，Java Agent 应用可通过自己的 Detector SPI 包装类接入，不依赖 Spring。

它将业务选定并最小化后的内容发给可信检测服务。只有合法、关联正确的明确 ALLOW 才能放行；服务不可用时拒绝受保护操作。此客户端没有内置语义模型，不等同于已经具备提示注入识别准确率，也不替代工具权限、租户 ACL 或已有本地策略。

## 1. 依赖与配置

```xml
<dependency>
  <groupId>io.github.umuo</groupId>
  <artifactId>agent-security-policy</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

```java
var settings = new RemoteDetectorSettings(
        URI.create("https://security.internal.example/v1/detect"),
        Duration.ofMillis(300),
        4,
        16 * 1024,
        "customer-policy-v1",
        Set.of(SecurityEvent.Phase.MODEL_INPUT,
               SecurityEvent.Phase.MODEL_OUTPUT,
               SecurityEvent.Phase.TOOL_INPUT));

var client = HttpClient.newBuilder()
        .connectTimeout(Duration.ofMillis(150))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();

var detector = new RemoteHttpDetector(
        client,
        settings,
        Map.of("Authorization", "Bearer " + tokenFromTrustedSecretStore),
        projectRedactor::toDetectionContent);
```

`projectRedactor` 是宿主实现的线程安全内容最小化组件，签名为 `String toDetectionContent(SecurityEvent event)`。它必须返回检测真正需要的文本，处理个人信息、凭据、内部文档等出站要求。没有隐式发送全文的默认构造器，也没有自动识别所有敏感信息的保证。若业务显式允许发送原文，可传 `SecurityEvent::text`；这表示选择发送原文，不是开启脱敏。

请求不自动携带 event.operation、用户、租户、权限、资源引用、父子 Agent 身份。身份若需要参与授权，应由可信宿主在服务端协议设计中单独处理，当前协议不支持把模型生成身份当作凭据。

参数约束：

| 参数 | 规则 |
| --- | --- |
| endpoint | 完整固定检测 URL，无 user-info、query、fragment。HTTPS 可用于真实服务；HTTP 仅接受 localhost、127.0.0.1、[::1] 本机测试地址 |
| timeout | 10ms～30s，检测器自身预算；包含内容准备后的剩余网络等待及完整响应体接收，不只是等待响应头 |
| maxConcurrent | 1～128，单个 Detector 实例同时执行 evaluate 的名额；满时立即拒绝，不建立额外等待队列 |
| maxRequestBytes | 1KiB～64KiB，完整 UTF-8 JSON 请求体上限，编码时检查，不能用 JSON 转义或多字节文本绕过 |
| policyVersion | 1～80 字符，字母、数字、下划线、点、短横线；服务端必须原样返回 |
| phases | 非空集合；仅检测这些阶段，其他阶段此 Detector 返回 ALLOW，其他本地检测器仍继续执行 |
| authenticationHeaders | 仅 Authorization、X-API-Key；拒绝大小写重复、控制字符、空白值及超过 4096 字符的值 |

HttpClient 禁用重定向、Authenticator 和 CookieHandler，防止隐式跳转或认证状态介入协议。TLS 信任库、mTLS 客户端证书、代理及 HTTP 执行资源由可信宿主配置；SDK 不创建 trust-all 配置；宿主需使用正常验证服务端证书的 SSLContext。不要从请求参数或模型文本动态选择 endpoint。HTTP 本机例外不用于生产跨机连接。

## 2. 服务端实现协议

请求：`POST`，`Content-Type: application/json`，协议字段固定为：

```json
{
  "schemaVersion": 1,
  "eventId": "a8c9b5a9-4dbc-4615-9bc1-2bdf3f6bb2b6",
  "phase": "TOOL_INPUT",
  "policyVersion": "customer-policy-v1",
  "content": "经过业务最小化的待检测内容"
}
```

正常完成检测后返回 HTTP 200 和 `Content-Type: application/json`，使用 UTF-8：

```json
{
  "schemaVersion": 1,
  "eventId": "a8c9b5a9-4dbc-4615-9bc1-2bdf3f6bb2b6",
  "policyVersion": "customer-policy-v1",
  "decision": "ALLOW"
}
```

拒绝时将 decision 改为 `DENY`。服务端应验证并执行客户端指定的策略版本；简单回显版本不证明执行了正确策略，需要服务端实现和验收保证。

响应体最多 16KiB，在流接收时限制。拒绝缺失字段、重复字段、未知字段、尾随 JSON、非法 UTF-8、错误类型、错误版本、错误 eventId，以及未知 decision。schemaVersion 必须为整数 1；不接受字符串 "1"。不接受 Content-Encoding，包括压缩响应。

服务端不能返回任意 ruleId 或解释文字直接进入安全日志。正常远程拒绝统一为 `remote-denied`；需要细化规则分类时，应另行设计经过白名单校验的协议版本。

## 3. 普通 Java 接入

```java
try (var audit = new BoundedAuditSink(yourAuditSink, Duration.ofSeconds(1), 128);
     var engine = new PolicyEngine(
             List.of(localPolicy, detector),
             audit,
             new DetectionLimits(Duration.ofMillis(500), 4))) {
    engine.check(event);
    // 必须在 check 正常返回后才执行副作用。
    performProtectedOperation();
}
```

此处 localPolicy、yourAuditSink、event 和业务操作来自宿主。实际工程应复用长期存在的 HttpClient、Detector、PolicyEngine，并由应用生命周期关闭。上例表达生命周期边界，不建议每个请求都新建实例。

PolicyEngine 的所有检测器共享总预算；示例 remote=300ms、engine=500ms，不能认为每个检测器都有额外 500ms。名额限制只针对单个 RemoteHttpDetector，多个实例的限制相互独立。派生引擎应尽量共享同一个远程 Detector。

内容最小化函数在调用线程运行。单独调用 evaluate 无法强制中断一个死循环函数，因此应通过 PolicyEngine 的有界检测线程执行；若函数不响应中断，外层仍拒绝，但线程/名额可能继续被占用。HTTP Future 超时/中断会请求取消，不保证服务端已经停止处理；服务端检测接口应无业务副作用，并以 eventId 关联或去重。

## 4. Java Agent 的 SPI 接入

应用增加一个公开无参 Detector 包装类，在构造时从可信配置和密钥来源创建并持有上述 detector，在 evaluate 中委托：

```java
package com.example.security;

public final class ProjectRemoteDetector implements io.agentsecurity.core.Detector {
    private final io.agentsecurity.core.Detector delegate;

    public ProjectRemoteDetector() {
        // 项目实现此工厂：固定端点、凭据、策略版本、阶段和内容最小化函数。
        // 构造阶段不要进行远程登录或耗时网络请求。
        delegate = ProjectSecurityConfiguration.remoteDetector();
    }

    @Override
    public io.agentsecurity.core.Decision evaluate(io.agentsecurity.core.SecurityEvent event) {
        return delegate.evaluate(event);
    }
}
```

`ProjectSecurityConfiguration` 是应用配置工厂，不是 SDK 自带类。业务 JAR 新增文件：

```text
META-INF/services/io.agentsecurity.core.Detector
```

文件内容为：

```text
com.example.security.ProjectRemoteDetector
```

业务继续以原来的 `-javaagent:...=...properties` 启动。在 properties 中按总检测链预算配置 `detector.timeout.millis`、`detector.max.concurrent`。SDK 不增加 remote.* 属性，不将凭据写入统一策略文件，不自动向任何地址发送内容。

Agent 的 SPI 发现按业务请求类派生，工厂可能被调用多次；如果需要全应用共享 HTTP 名额，应在应用类加载器范围内共享同一个 RemoteHttpDetector，而不是在每个包装类中创建独立实例。构造失败、加载超时仍按原有 SPI 机制拒绝。独立 SDK 和 Boot SPI 的可执行接入例子见仓库中的 RemoteHttpDetectorTest 和 RemoteFixture。

## 5. 故障与运维

| ruleId | 含义 |
| --- | --- |
| remote-denied | 服务端正常完成检测并明确拒绝 |
| detector-remote-auth | 完整收到 401 或 403 |
| detector-remote-http | 完整收到其他非 200 状态，包括 3xx、429、5xx |
| detector-remote-protocol | 响应头/JSON/关联字段不符合协议 |
| detector-remote-request | 内容准备失败、返回 null、或请求超限 |
| detector-remote-capacity | 当前实例名额已满 |
| detector-remote-timeout | 检测器自身截止时间或 HTTP 请求超时 |
| detector-remote-interrupted | 调用线程中断，保留中断标志 |
| detector-remote-transport | 连接、TLS、响应体超限/不完整或其他 HTTP 客户端故障 |

外层 PolicyEngine 总预算更早到期时，可能得到 `detector-timeout`；外层线程池已满时是 `detector-capacity`。不要要求所有超时都表现为 remote 前缀。通过引擎执行时，detector-remote-* 会进入 DETECTOR_FAILURE 遥测；正常 remote-denied 是 DENY。

没有主动重试、失败放行、缓存旧 ALLOW 或自动熔断放行。HTTP 客户端及网络层行为不构成恰好一次送达承诺。静态认证头不可变，凭据轮换通过宿主新建 Detector 并管理切换实现；本轮不提供自动轮换。

一次模型调用可能经过多个拦截边界并产生多个独立 eventId；这不等于客户端重试。当前 Boot 允许场景覆盖三个 MODEL_INPUT 检查事件，拒绝场景在第一个事件阻断。

`detectorHealth().errors()` 统计执行异常，远程错误通常作为拒绝 Decision 返回，因此应通过安全事件的 DETECTOR_FAILURE 和稳定 ruleId 识别，不能只看执行池 errors。

客户端不打印请求、响应、凭据或原始异常信息。宿主 HTTP 调试日志、代理与远程服务日志仍需要自行控制。遥测导出失败可以丢弃遥测，与此处检测失败必须拒绝的语义不同。

## 6. 验收范围

本机 HTTP 测试验证：合法 ALLOW、DENY、401/403、503、重定向不跟随、请求内容最小化、关联与版本校验、响应重复/未知字段、非法 UTF-8、响应体上限与停滞、内容编码上限、并发名额、线程中断和配置拒绝。策略引擎测试明确核对违规分支副作用为零。

Boot 独立 JVM 验证应用 SPI 包装远程客户端，允许场景实际调用模型一次；拒绝、认证失败和非法协议时模型调用次数为零，并检查 JSONL 审计不含测试正文或令牌。

不代表已接入真实生产检测服务，不保证检测效果，也未完成此客户端的跨机 TLS/mTLS、断网长压、服务端容量或误报/漏报验收。真实 Collector TLS 验收属于另一条可观测性链路，不能移用为本客户端的 TLS 验收证据。


本轮执行证据：2026-09-28 完整 release.sh 通过 347 项测试（其中本客户端新增 23 项，Boot 新增 4 项），四个运行时 JAR 隔离重建一致。最终本机矩阵为 JDK 21.0.4；源代码按 Java 17 编译，未据此声明远端 JDK 17 CI 已通过。发布目录保留模块测试 XML、SBOM、build-evidence.json 与 SHA256SUMS。
