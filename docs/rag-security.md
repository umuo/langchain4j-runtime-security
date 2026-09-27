# RAG 运行时拦截

当前适配固定 LangChain4j 1.20.0 的 `ContentRetriever` 与 `RetrievalAugmentor`，支持同步和 CompletableFuture 路径。检索发生在模型调用之前，因此检索前检查用于阻止未授权读取，检索后检查用于阻止不可信结果继续进入增强流程。接口概念见 [LangChain4j 官方 RAG 文档](https://docs.langchain4j.dev/tutorials/rag/)；实现和本地验证以项目固定版本的源码为准，不以在线最新 API 作为兼容承诺。

## 快速验证

```bash
bash scripts/verify.sh

# 无 Agent 对照：检索一次，模型调用一次
java -jar demo/target/agent-security-demo.jar rag-output

# 检索前拒绝：RETRIEVAL_CALLS=0，modelCalls=0
bash scripts/demo.sh rag-input

# 检索结果拒绝：RETRIEVAL_CALLS=1，modelCalls=0
bash scripts/demo.sh rag-output

# 正常放行：RETRIEVAL_CALLS=1，modelCalls=1
bash scripts/demo.sh rag-allowed
```

该 demo 只依赖 LangChain4j，没有安全 SDK API 调用；它通过 `AiServices.contentRetriever` 注册 lambda 检索器。身份策略仍需应用显式接入 [可信上下文](security-context.md)。所有场景使用本机内存数据，不访问外部知识库。

## 检测事件

| phase | 检查时机 | 进入检测的内容 |
| --- | --- | --- |
| `AUGMENTATION_INPUT` | augment／augmentAsync 方法体之前 | 当前消息，以及查询元数据中的 chatMessage、systemMessage、chatMemory 文本 |
| `RETRIEVAL_INPUT` | retrieve／retrieveAsync 方法体之前 | 实际查询文本（包括改写后的查询），以及同样的消息元数据 |
| `RETRIEVAL_OUTPUT` | 检索结果交付给调用方／后续增强组件之前 | 整批 TextSegment 正文及其文档元数据的键和值 |
| `AUGMENTATION_OUTPUT` | 增强结果交付之前 | 增强消息，以及返回的 contents 正文和文档元数据 |

同一结果批次全部通过后才返回；任意内容拒绝则整批失败。仍沿用本地 `deny.text`、检测器 SPI、检测总预算和审计确认机制。异步输入拒绝交付失败 future，输出拒绝使包装后的 future 失败；取消尽力传递给源 future，不保证终止已经发出的外部 I/O。

`SecurityEvent.operation()` 是执行组件的实现类全名。隐藏 lambda 使用 `lambda:` 加声明宿主类名，避免每次 JVM 运行的动态后缀。该值提供组件层面的来源标签，**不是文档来源认证或资源归属证明**，也不能区分同一类的不同数据源实例。内置日志不记录 operation 或文档内容。

已插桩的具名实现支持直接调用。以下框架分发位置另外包装接口，覆盖隐藏 lambda：

- `AiServices.contentRetriever` 和 `AiServices.retrievalAugmentor` 注册入口。
- `DefaultRetrievalAugmentor` 的 queryRouter 返回的检索器集合。

自定义 augmentor 内部若绕过这些位置直接调用隐藏 lambda，该内部检索调用未独立受控；外层增强入口若受控，仍检查整体输入／输出。直接从业务调用未注册的隐藏 lambda、自行实现并绕开这些接口的 SQL／向量库／HTTP 操作也不覆盖。业务不应依赖包装后组件的对象身份或强制转换成具体实现类。

## 检索器准入与身份

主 properties 可限制允许的实现类：

```properties
allow.retrievers=com.example.CustomerKnowledgeRetriever
context.required=true
rag.max.contents=256
rag.max.metadata.entries=64
```

`allow.retrievers` 精确匹配 `RETRIEVAL_INPUT.operation()`，区分大小写；未设置表示不启用该白名单，显式空值拒绝所有检索器，未知项拒绝为 `retriever-not-allowed`。有多层具名包装器时，各受保护层都需满足规则。需要不同权限的数据源应使用可区分的实现类或独立的业务授权检查，不要用共享 lambda 宿主标签区分它们。

白名单控制组件准入；用户权限可由检测器 SPI 使用 `event.context()` 判定，例如：

```java
if (event.phase() == SecurityEvent.Phase.RETRIEVAL_INPUT) {
    var context = event.context();
    if (context == null) return Decision.deny("missing-security-context");
    if (!context.permissions().contains("knowledge:read"))
        return Decision.deny("rag-permission-denied");
}
return Decision.allow();
```

这段是插件示例，`knowledge:read` 不是 Agent 内置的默认权限要求。实际数据源必须使用可信租户／用户身份落实 ACL 或查询过滤；Agent **不会自动给向量查询加 tenant filter**。查询的 memoryId、invocationParameters、文档 metadata 即使含有 tenantId，也不会被当作可信身份。输出检测不能撤销已经发生的数据库／网络读取。

## 异步与资源边界

检索和增强 future 完成期间恢复发起时身份快照，并在完成后恢复工作线程原身份。`DefaultRetrievalAugmentor` 的默认／自定义执行器在任务提交时捕获上下文；其 queryTransformer、queryRouter、contentAggregator 异步完成也传播快照，覆盖中间步骤在其他线程完成的情况。组件内部自行创建的任务仍需 SDK 显式传播；不保证任意自定义 RAG 编排器或 Reactor 管道自动继承身份。

`rag.max.contents` 默认 256，范围 1～4096；限制一次检查的结果数量、历史消息数量以及已包装路由返回的检索器数量。`rag.max.metadata.entries` 默认 64，范围 1～1024，限制每个 TextSegment 文档元数据的条目数。超限返回 `rag-content-limit`。整批正文、元数据和增强消息的累计文本受 `max.text.chars` 限制，超限返回 `text-limit`；这些是 SDK 检查上限，不限制数据源事先分配的内存或所有并发检索数量。

文档元数据只接受固定版本支持的 String、UUID、Integer、Long、Float、Double；其他类型拒绝为 `unsupported-rag-metadata`。空结果列表允许；null 检索结果／future 拒绝为 `null-result`，错误对象形状拒绝为 `adapter-shape-error`。AugmentationResult 可以省略 contents，其增强消息仍必检。

当前不通用序列化 `Content.metadata()` 中的评分／检索器对象，也不解析任意 invocationParameters；检查范围仅为表中字段。不要依赖 SDK 对其中任意业务对象做检测。适配错误和数量／形状拒绝可能发生在策略引擎之前，因此不保证每次都有独立 DENY 审计事件。

## 验证与限制

Boot 独立 JVM 验证同步／异步检索、原生异步查询改写与路由、阻塞组件 offload、默认／自定义并发执行器、lambda 分发、具名实现直接调用、用户权限缺失、身份缺失、改写后查询拒绝、文档元数据拒绝、自定义增强器输出拒绝、批次数量上限和 null future。拒绝前后的读取数／模型调用数均有断言；完成线程故意安装另一身份，以验证恢复与不串租户。普通 Java 示例另有无 Agent 对照。

增加了四个 phase 枚举值，日志消费者和检测器需接受这些值；JSONL 结构仍为 schema 2。插件若仅处理模型／工具阶段，不会自动获得业务 RAG 权限规则。部分受保护调用有重复检查和审计，尚未自动去重。

尚未验证真实向量数据库、数据库 ACL、所有检索器 provider 和长时间并发压力。字面规则不是语义提示注入检测器；允许结果也不证明文档可信。MCP 尚未接入；memory 独立边界见 [专用适配](memory-security.md)。
