# 可信身份上下文接入

内容规则可以只通过 `-javaagent` 接入；用户／租户授权需要应用提供已经验证的身份。Agent 无法从 prompt、工具参数或未经验证的 HTTP header 判断真实身份。

多 Agent 任务应在认证后使用 [AgentRuntime](multi-agent-security.md) 创建委托身份；普通上下文的传播不会自动生成父子关系。

## 认证入口

业务应用依赖与 Agent 同一构建版本的 `io.github.umuo:agent-security-core:0.1.0-SNAPSHOT`。在应用完成认证和权限查询后，为每次业务 run 创建上下文：

```java
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;

SecurityContext context = SecurityContext.authenticated(
        authenticatedTenantId, authenticatedUserId, verifiedPermissions);
try (var scope = SecurityContexts.open(context)) {
    return assistant.chat(userMessage);
}
```

`authenticated` 只是命名清晰的快照工厂，**不会验证 JWT、session 或权限**。调用方必须从可信认证系统取得参数；绝不能使用模型输出／工具参数构造这些值。工厂生成随机 UUID `runId`；权限集合复制为不可变集合。tenantId、principalId、权限标识均限 1～128 位字母、数字或 `@._:-`，权限最多 128 个。对展示名等其他格式应由应用映射到稳定的内部标识。

作用域必须在创建线程上按逆序关闭，推荐始终使用 try-with-resources。结束时恢复原上下文，最外层结束后移除 ThreadLocal。线程不继承身份；没有上下文的快照会明确清除执行线程上的环境身份，防止借用其他请求的权限。

主 properties 开启：

```properties
context.required=true
tool.policy.path=context-tool-policy-example.json
```

`context.required` 默认 false，以兼容只用内容规则的应用；启用后，进入策略引擎的任何无上下文受保护事件都拒绝为 `missing-security-context`。即使未启用全局要求，工具策略使用权限或身份绑定时，该工具仍要求上下文。身份信息不会自动补全；先完成应用接入再启用要求。

## 工具权限与参数绑定

示例 [context-tool-policy-example.json](../config/context-tool-policy-example.json) 仅允许 `lookup`，要求 `customers:read` 权限，且参数 tenantId 必须等于可信上下文 tenantId：

```json
{
  "schemaVersion": 1,
  "permissions": {"lookup": ["customers:read"]},
  "tools": {
    "lookup": {
      "type": "object",
      "required": ["tenantId"],
      "properties": {
        "tenantId": {"type": "string", "equalsContext": "tenantId"}
      }
    }
  }
}
```

字段还可绑定 `principalId`，可嵌套在对象／数组规则内，和 enum、长度限制同时生效。缺少权限拒绝为 `permission-denied`，不一致的参数拒绝为 `tool-argument-policy`；受保护工具执行前完成检查。JSON 转义后再比较，不能用转义绕过身份匹配。

这些规则不验证任意 customerId 的真实归属。数据库、文件、网络服务仍需执行资源鉴权。权限快照目前没有自动过期／撤销机制；长任务的重新授权由应用负责。

## 异步边界

对于已适配 LangChain4j 1.20.0，Agent 捕获以下边界的上下文：

| 边界 | 行为 |
| --- | --- |
| 模型异步 future | 调用时捕获；返回检测及 future 完成期间安装快照，随后恢复完成线程原身份 |
| 回调模型流 | 包装 handler 时捕获；事件检测、回放及超时通知使用该快照 |
| Flow 模型流 | 创建时绑定快照；订阅、上游信号、下游回调、request／cancel 使用该快照 |
| 框架默认执行器 | 在 `DefaultExecutorProvider` 返回的执行器提交任务时捕获 |
| 自定义并发工具执行器 | 包装 `ToolService.executeToolsConcurrently(Executor)` 传入的执行器，提交时捕获 |
| 默认 RAG 编排器 | 包装其默认／自定义执行器，以及 queryTransformer／queryRouter／contentAggregator 的 future 完成；检索与增强 future 也保存调用时快照，详见 [RAG 边界](rag-security.md) |
| Memory／Store future | 保存身份和请求资源快照，读取结果检查与完成回调恢复该快照；自建数据库任务需组件显式传播，详见 [Memory 边界](memory-security.md) |
| 检测器工作线程 | 使用 `SecurityEvent.context()` 的快照；调用结束恢复线程状态 |

异步调用应在作用域内发起，然后可以关闭发起线程的作用域，交由已适配路径继续：

```java
CompletableFuture<String> result;
try (var scope = SecurityContexts.open(context)) {
    result = asyncAssistant.chat(userMessage);
}
return result;
```

不保证任意 `thenApplyAsync`、已完成 future 上后注册的业务回调或应用自建线程池自动继承身份。业务异步任务可显式装饰执行器：

```java
Executor securedExecutor = SecurityContexts.executor(applicationExecutor);
try (var scope = SecurityContexts.open(context)) {
    securedExecutor.execute(() -> assistant.chat(userMessage));
}
```

装饰器在**提交任务时**捕获，不能先在无上下文处排队再期待工作线程推断身份。单个任务可用 `SecurityContexts.wrap(Runnable)` 或 `wrap(Callable)`；`executorService` 提供 ExecutorService 形式，其关闭会关闭底层执行器，生命周期由应用管理。

Publisher 创建时的空身份也是固定快照，不借用订阅／回调线程的身份。有身份的 Publisher 在另一上下文（包括另一 runId）中订阅会拒绝为 `security-context-mismatch`；在无环境上下文的线程订阅则恢复创建时快照。不要跨请求缓存 Publisher。全局要求身份时，应始终在认证作用域内创建 Publisher。

不自动读取 Spring Security、Reactor Context、OpenTelemetry baggage 或任意 ThreadLocal，也不插桩所有 JDK Executor。未覆盖异步路径需要应用显式传播并增加集成测试；`context.required=true` 可让传播丢失表现为拒绝，但不保证尚未插桩的操作受控。

## 检测与审计

检测器优先使用 `event.context()`，它与事件一起形成不可变快照；不要从 `event.text()` 解析可信身份。SDK 当前只隔离正常应用的请求上下文，不防御能任意执行 JVM 代码的恶意插件。

JSONL schema 2 添加可空 `runId`，用于关联一次 run 内不同保护层的检测。eventId 仍表示单次检测，没有自动去重或 tool-call ID。内置日志不记录 tenantId、principalId、permissions 或文本；业务／插件自己的日志仍由其实现负责。升级日志消费者须同时处理历史 schema 1 与 schema 2，详见 [运行手册](operations.md)。当前 schema 3 另增加委托执行字段，兼容说明见 [多 Agent 安全](multi-agent-security.md)。

本地测试覆盖身份缺失、权限缺失、参数伪造、同步／异步 AI Services、默认／自定义并发工具执行器、两个租户重叠执行、流式回调／Flow、异步完成线程带另一身份、异常回调和作用域恢复。测试矩阵仍限于当前固定版本，不构成任意第三方异步组件的兼容承诺。
