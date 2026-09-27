# ChatMemory 与持久化存储防护

固定适配 LangChain4j 1.20.0 的 `ChatMemory` 与 `ChatMemoryStore`，支持同步方法及接口中的 CompletableFuture 方法。概念和持久化接口参见 [官方 Chat Memory 文档](https://docs.langchain4j.dev/tutorials/chat-memory/)。在线文档可能更新；兼容承诺仍以项目固定版本及测试矩阵为准。

## 检测边界

| phase | 对应操作 | 行为 |
| --- | --- | --- |
| `MEMORY_READ_INPUT` | messages／messagesAsync、getMessages／getMessagesAsync | 读取前授权；拒绝时原方法体不执行 |
| `MEMORY_READ_OUTPUT` | 上述读取操作返回 | 整批检查历史消息后交付，返回独立的可修改列表 |
| `MEMORY_WRITE` | add／set 的单条、批量、异步方法；updateMessages／updateMessagesAsync | 检查整个待写批次后执行；记录的是写入前决策 |
| `MEMORY_DELETE` | clear；deleteMessages／deleteMessagesAsync | 清空或删除前授权 |

消息正文、thinking、工具调用名／参数和工具返回文本沿用既有消息适配；未支持的消息／非文本内容拒绝。读取结果中的危险内容在到达模型之前被阻断，但读取本身已经发生。写入和删除没有自动回滚；ALLOW 审计不表示存储操作成功。

默认批量 `add` 可能逐条写入，默认 `set` 可能先 clear 再 add。Agent 先将 Iterable／数组收集为有界快照并检查整批，再替换传入集合后执行，避免第二条消息被拒绝时第一条已经写入，或先清空再发现输入不合规。单次 Iterable 只被消费一次；这不提供数据库事务，嵌套检查、存储故障、并发写入仍可能导致部分变更。

## 配置

```properties
context.required=true
memory.read.permission=memory:read
memory.write.permission=memory:write
memory.delete.permission=memory:delete
memory.max.messages=256
```

三个 permission 配置分别要求可信上下文包含对应权限；缺少身份拒绝为 `missing-security-context`，权限不足为 `permission-denied`。权限值限 1～128 位字母、数字或 `@._:-`，空值配置错误。未设置某项时，不隐式要求该项权限；本地文本规则、SPI 和全局身份要求仍生效。

窗口 memory 的 add 可能先读取旧消息，因此通常同时需要读和写权限。默认 set 若调用 clear，还需要删除权限。应根据真实实现和业务最小权限策略配置，不能依赖某条方法名只触发一种底层操作。

`memory.max.messages` 默认 256，范围 1～4096，限制每批写入和每次读取的消息数量，超限 `memory-message-limit`。累计消息文本继续受 `max.text.chars` 限制。限制的是 SDK 处理量，不是存储容量或整个应用的堆内存配额；不能中断恶意或永久阻塞的迭代器代码。null 消息／批次拒绝，null 读取结果或 future 拒绝为 `null-result`；异步 void 成功的 null 值正常允许。

## 会话资源与跨租户权限

内存 ID 是调用方请求的资源，**不等于经过认证的用户身份**。事件新增可空 `resource()`，memory 事件携带 `ResourceRef(type, id)`，例如 `memory:string` 与 `private-session`。支持的 ID 类型为 String、UUID、Integer、Long，分别使用不同的 type，防止字符串 `"42"` 与整数 `42` 在策略中混淆。其他类型拒绝为 `unsupported-memory-id`，字符串化长度超过 1024 拒绝为 `memory-id-limit`。

应用插件可将 `event.resource()` 与 `event.context()` 交给可信 ACL 查询，例如：

```java
if (event.resource() != null && event.resource().type().startsWith("memory:")) {
    SecurityContext caller = event.context();
    if (caller == null) return Decision.deny("missing-security-context");
    // ownershipService 必须查询可信授权数据，不能根据模型传入的租户字段自行授予权限。
    if (!ownershipService.canAccess(caller.tenantId(), caller.principalId(),
            event.resource(), event.phase())) return Decision.deny("memory-owner-denied");
}
return Decision.allow();
```

`ownershipService` 由应用实现；内置权限标识不替代逐会话 ACL。不要采用“第一个访问者自动拥有此 memoryId”的隐式授权。持久化存储必须保留自身权限校验，SDK 不自动重写 memoryId 或创建租户分区。

resource 仅供内存中的检测器使用，内置 JSONL 和 stderr 不记录 ID、身份或历史内容，ResourceRef／SecurityEvent 的 toString 也不输出 ID。JSONL 仍为 schema 2，但消费者需接受四个新增 phase。SDK／Agent／插件须同版本重新构建；旧构造方法保留源码兼容入口，SNAPSHOT 不保证二进制兼容。

## 覆盖与异步约束

具名 ChatMemory／ChatMemoryStore 实现和接口 default 方法直接插桩。`ChatMemoryService.getOrCreateChatMemory/getChatMemory` 的返回对象另外包装，覆盖 AI Services 缓存中取出的代理 memory；MessageWindowChatMemory／TokenWindowChatMemory builder 的 `chatMemoryStore` 注册入口也包装 store。组件包装会改变对象身份和具体实现类型，业务不能依赖强转包装结果或对象身份相等。

future 完成时用调用时的身份和资源快照检查结果，再恢复完成线程原身份；取消尽力传播给源 future。组件内部新建线程执行实际数据库操作的身份仍由该组件负责，包装只保证已适配边界和完成回调，不会把所有线程变成受控线程。

没有覆盖直接调用未注册 JDK 动态代理的 memory/store、绕过接口的数据库访问、ChatMemoryProvider 创建对象时的任意副作用、缓存枚举／evict 操作或外部会话管理 API。`id()` 仅用来识别资源，不作为读取历史的授权边界。自定义 store 还需验证访问控制、并发一致性、序列化和事务。

本地测试使用真实 AI Services、MessageWindowChatMemory 和计数存储，验证批量 add/set 在拒绝时零写入／零删除、读取结果拒绝时零模型调用、权限与跨租户 ACL 拒绝、直接 store 调用、异步 void／读取和工作线程身份恢复。真实持久化数据库、TokenWindowChatMemory 的端到端行为及长期并发压力尚未验证。
