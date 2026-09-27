# 源码学习指南：从一次工具阻断开始

如果还不熟悉框架的整体工作方式，先阅读 [图解架构](architecture-explained.md)：从检查站的职责、放行／阻断过程，再回到下面的源码路线。

如果第一次看这个仓库，建议从 **`Demo.main` 的 `tool` 场景开始，看见工具被阻断，再进入 `PolicyEngine.check` 理解决策，最后回头看 Java Agent 如何把两者连接起来**。第一次只追同步工具调用，不必同时理解流式状态机、RAG 和所有 Byte Buddy 匹配规则。

本文按当前代码布局编写，命令均在仓库根目录执行。源码按 Java 17 编译，本地验证使用 JDK 21；Agent 固定适配 LangChain4j 1.20.0。文中的方法名比行号更适合定位，行号会随后续重构变化。

## 一、先确定你的学习目标

| 你的目标 | 推荐阅读范围 |
| --- | --- |
| 给自己的项目写策略插件 | 第 1～3 步、第 5 步，再读 [SDK 扩展指南](sdk-extension.md) |
| 理解无侵入拦截如何实现 | 第 1～6 步，重点跟一次 `sendEmail` 的输入拒绝 |
| 维护异步、身份和流式保护 | 在同步链路读懂后，继续第 7～9 步 |
| 增加框架适配或准备生产部署 | 完成第 10～12 步，并阅读 [生产验收清单](production-readiness.md) |

学习时始终带着四个问题：**在哪里拦截？拿到了什么信息？什么时候决定放行？失败时业务动作是否已经发生？**

## 二、项目地图：先认识五个模块

| 模块 | 作用 | 第一遍关注点 |
| --- | --- | --- |
| `demo` | 不依赖安全 SDK 的 LangChain4j 演示应用 | 工具计数、模型计数和 Agent 有无的差异 |
| `agent-security-core` | 无第三方运行时依赖的安全内核 | 事件、决策、检测器、策略引擎、上下文、审计 |
| `agent-security-policy` | 结构化工具参数策略 | 严格 JSON 解析、规则编译与校验 |
| `agent-security-javaagent` | JVM 启动时安装的拦截层 | 启动装配 → 类型和方法匹配 → Advice → Bridge |
| `integration-spring-boot` | Boot 集成验证应用 | nested JAR 类加载、应用 SPI、官方客户端及本机 HTTP/SSE |

普通 Java 接入不经过 Spring Boot 模块。`integration-spring-boot` 是验证夹具，不是 SDK 启动的必需依赖。

Agent 内部目录按职责组织：

```text
io.agentsecurity.agent
├── SecurityAgent                JVM premain 入口
├── AgentBootstrap               配置和资源装配
├── instrumentation
│   ├── AgentInstrumentation     安装类型／方法匹配与增强
│   ├── FailClosedTransformer    插桩失败处理
│   └── advice                   各边界的进入／退出逻辑
├── bridge                       将 LangChain4j 对象转换成安全事件
└── stream                       流式缓冲、背压、取消和超时
```

读代码时可用 IDE 的“搜索类”和“查找方法”；命令行先查源码位置：

```bash
rg --files -g '*.java' -g '!target/**' -g '!.cache/**'
rg -n 'class PolicyEngine|void check\(' agent-security-core/src
rg -n 'class SyncAdvice|void before\(' agent-security-javaagent/src
```

## 第 1 步：先运行一组有／无 Agent 对照

### 要做什么

第一次先构建运行所需的 Agent 与普通 demo，暂时跳过测试执行：

```bash
mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 \
  -pl demo,agent-security-javaagent -am -DskipTests package

# 不加载 Agent：只运行普通 LangChain4j 应用。
java -jar demo/target/agent-security-demo.jar tool

# 加载 Agent：使用 config/demo.properties。
bash scripts/demo.sh tool

# 再跑一个正常放行的场景。
bash scripts/demo.sh allowed
```

构建仍会检查格式和规范。上述示例使用内存模型及工具，不需要模型 API key。

### 看哪些源码

1. `demo/src/main/java/io/agentsecurity/demo/Demo.java`：先读 `main` 中的 `tool`／`allowed` 分支。
2. 同一文件中的 `MockModel.respond()`：它怎样生成工具请求、统计模型调用。
3. `CustomerTools.sendEmail()`、`readCustomer()`：工具方法体第一步增加计数。
4. `scripts/demo.sh`：真正改变行为的是 JVM 的 `-javaagent` 参数。
5. `config/demo.properties`：`deny.tools` 包含 `sendEmail`。

### 看见什么算学会

| 场景 | 重点结果 |
| --- | --- |
| 无 Agent 的 `tool` | `blocked=false`，`toolCalls=1` |
| 启用 Agent 的 `tool` | `blocked=true`，`toolCalls=0` |
| 启用 Agent 的 `allowed` | `blocked=false`，`toolCalls=1` |

先看业务计数，再看日志。`instrumented=...` 只表示增强过某个类型，不能单独证明工具没有执行。不要用检测事件数量代替业务调用次数：同一次调用可能经过多层保护。

**自测问题：**`sendEmail()` 内部没有 SDK 调用，为什么工具计数仍然是零？先保留这个问题，第 4 步回答。

## 第 2 步：理解安全内核的四个基本类型

在 `agent-security-core/src/main/java/io/agentsecurity/core/` 按顺序阅读：

| 顺序 | 类型 | 需要记住的内容 |
| --- | --- | --- |
| 1 | `SecurityEvent` | 一次检测的阶段、操作名、文本、身份快照及可空资源引用 |
| 2 | `Decision` | 只表示允许／拒绝及稳定规则 ID，不负责修改内容 |
| 3 | `Detector` | `evaluate(event)`：输入一个事件，返回一个决策 |
| 4 | `SecurityBlockedException` | 把拒绝交给业务调用方，`ruleId()` 可用于识别原因 |

先只理解 `TOOL_INPUT`，其 `operation` 是工具名、`text` 是参数 JSON。其他阶段的字段语义见 [SDK 扩展指南](sdk-extension.md)。

**练习：**在 IDE 中查看下面表达式，说明每个值分别代表什么：

```java
new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, "sendEmail", "{}");
Decision.deny("tool-denied");
```

这些是 API 表达式，不是独立可执行程序，也不会自行执行或拦截工具。需要完整可运行示例时使用扩展指南的 `PluginSmoke`。

## 第 3 步：只跟策略引擎，暂时不看插桩

### 阅读顺序

1. `PolicyEngine.check(event)`。
2. `LocalPolicy.evaluate(event)`，只看工具名拒绝分支。
3. 回到 `PolicyEngine.check`，看审计和异常抛出的位置。
4. 打开 `PolicyEngineTest` 的 `denialShortCircuitsDetectorsAndAudits`。

调用顺序可以记为：

```text
收到事件
  → 计算检测链截止时间
  → 逐个执行检测器
  → 第一次拒绝即停止继续检测
  → 写入决策审计并确认成功
  → 拒绝则抛异常；全部允许才正常返回
```

注意：拒绝也会审计，但不是每个检测器都生成单独审计；审计失败同样阻断。内置成本可控的策略在当前线程执行，扩展检测器进入有界线程池。

### 单独运行相关测试

```bash
mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 \
  -pl agent-security-core -am \
  -Dtest=PolicyEngineTest -Dsurefire.failIfNoSpecifiedTests=false test
```

在 IDE 给 `check` 中的决策赋值、`audit.accept` 和抛出异常处下断点，比一开始调试整个应用容易。自定义 Detector 执行在工作线程，单步时留意线程切换。

**自测问题：**第一个检测器拒绝后，第二个还会运行吗？审计写入失败时会放行业务吗？正常返回表示工具已经成功执行了吗？正确理解应分别是“不会”“不会”“不表示”。

## 第 4 步：回答“Agent 如何把检查插进业务调用”

### 4.1 先看启动链路

从 `agent-security-javaagent/pom.xml` 中的 `Premain-Class` 找到入口，然后按下面顺序跟：

```text
JVM 读取 -javaagent
  → SecurityAgent.premain
  → AgentBootstrap.initialize
      → 检查是否已有 LangChain4j 类被提前加载
      → 读取配置、创建检测器及审计
      → 创建 PolicyEngine，初始化 Bridge 和流资源
  → AgentInstrumentation.install
      → 注册类加载时使用的转换器
  → 应用 main 开始执行
```

`premain` 是 JVM 启动入口，**不是每次请求都会执行的入口**。`AgentBootstrap` 负责装配，第一次不必逐个背配置键。

### 4.2 再看类型和方法匹配

在 `AgentInstrumentation.install` 中只找三处：

- `modelType`／`toolType`：哪些接口及实现属于候选目标。
- `modelMethod`／`toolMethod`：方法名、参数类型等签名约束。
- `Advice.to(SyncAdvice.class)` 的绑定位置：同步方法最终使用哪个 Advice。

这里重点拦截 `ToolExecutor` 等框架执行边界，**不是给每一个业务 `@Tool` 方法直接织入检查**。因此直接调用业务工具方法、绕开已支持框架边界，不会因为方法上有 `@Tool` 就自动受到同样保护。

不用先研究 Byte Buddy 所有 API。第一遍理解 `named`、`takesArgument`、`hasSuperType` 等匹配含义，以及匹配结果决定是否安装 Advice 即可；具体以当前表达式为准。

### 4.3 跟一次输入拒绝

阅读 `instrumentation/advice/SyncAdvice.java`，再跳转到 `bridge/Bridge.java`：

```text
Demo 通过 AiServices 发起调用
  → 模型返回 sendEmail 工具请求
  → LangChain4j 进入已增强的工具执行方法
  → SyncAdvice.enter 对应的插入逻辑
  → Bridge.before(request)
      → 校验边界／版本
      → 提取 name、arguments
      → 构造 TOOL_INPUT 事件
  → PolicyEngine.check
  → LocalPolicy.evaluate 返回拒绝
  → 审计后抛 SecurityBlockedException
  → 原工具执行方法体不执行
  → CustomerTools.sendEmail 不执行，toolCalls 保持 0
```

正常成功返回的同步调用走 `SyncAdvice.exit → Bridge.after → PolicyEngine.check` 检查结果。输入拒绝不能当作“调用工具后检查”；输出拒绝也不能回滚已经发生的工具副作用。

### 4.4 推荐断点与观察值

| 断点位置 | 看什么 |
| --- | --- |
| `SecurityAgent.premain` | Agent 是否真正启动、配置路径是什么 |
| `Bridge.before` | `request.getClass()`、请求属于模型还是工具 |
| `PolicyEngine.check` | `event.phase()`、`operation()`、决策和审计顺序 |
| `LocalPolicy.evaluate` | 哪个配置条件触发拒绝 |
| `CustomerTools.sendEmail` | 拒绝场景应该进不来 |
| `Bridge.after` | 只在成功结果路径观察输出检查 |

Byte Buddy Advice 默认内联进目标方法，不能把它当成稳定存在的普通 Java 调用栈帧；Advice 源码断点可能不命中。优先给实际被调用的 `Bridge`、`PolicyEngine` 和业务方法下断点。

需要在本机 IDE 远程调试时，可以使用：

```bash
java \
  -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=127.0.0.1:5005 \
  -javaagent:agent-security-javaagent/target/agent-security-javaagent.jar=config/demo.properties \
  -jar demo/target/agent-security-demo.jar tool
```

IDE 连接本机 5005 端口，使用本仓库当前源码。`suspend=y` 会等待调试器后再启动。不要在生产环境复制这条调试启动命令。

**本步完成标志：**能不看文档画出“工具执行边界 → Advice → Bridge → PolicyEngine → Detector”，并解释哪个位置保证零工具副作用。

## 第 5 步：跟一个业务专属策略如何被发现

同步链路读懂后，读 `Bridge.newEngines()` 内的 `ClassValue.computeValue`：

```text
某边界对象对应的类首次需要组合引擎
  → 使用该类的 ClassLoader
  → ServiceLoader.load(Detector.class, loader)
  → PolicyEngine.loadDetectors 限制构造耗时
  → withAdditionalDetectors 追加应用策略
  → 缓存该类对应的组合引擎
```

接着看：

- `integration-spring-boot/src/main/resources/META-INF/services/io.agentsecurity.core.Detector`。
- `integration-spring-boot/src/main/java/io/agentsecurity/fixture/FixtureDetector.java`。
- `BootIT` 中的 `plugin`、`plugin-timeout`、`plugin-error` 场景。

关注两个容易忽略的点：SPI 文件不存在可能只是发现零个扩展，并不自动报错；`ClassValue` 缓存也不意味着一个插件全 JVM 只构造一次。检测器必须线程安全，不能依赖跨 JAR 的发现顺序。

**练习：**按 [SDK 扩展指南](sdk-extension.md) 完成 `OrderSecurityDetector` 和 `PluginSmoke`，先跑独立自检，再接到实际业务工具入口。不要为了让例子工作去修改 `Bridge` 静态状态。

## 第 6 步：把“失败时拒绝”逐项读清楚

现在才读资源和异常处理，以免刚开始被线程池实现分散注意力。

| 阅读对象 | 核心问题 | 对应测试 |
| --- | --- | --- |
| `DetectionExecutor.run`、`DetectionLimits` | 排队耗时算不算预算？插件不响应中断怎么办？ | `DetectionLimitsTest` |
| `BoundedAuditSink.accept`、`FileAuditSink` | 写入超时或失败后为什么持续拒绝？如何限制日志增长？ | `BoundedAuditSinkTest`、`FileAuditSinkTest` |
| `FailClosedTransformer.transform` | 普通 transformer 异常可能被 JVM 忽略，如何避免原始类继续执行？ | `FailClosedTransformerTest` |
| `Bridge.verifyVersion` | 什么时间检查版本？未知版本为何拒绝？ | `demo/AgentIT` 的相关场景 |

`DetectionLimitsTest` 优先读：

1. `slowDetectorTimesOutWithoutAllowingOperation`。
2. `chainUsesOneBudgetRatherThanOneTimeoutPerDetector`。
3. `uninterruptibleDetectorCannotCreateUnboundedWorkersOrQueuedRequests`。
4. `pluginConstructionIsAlsoTimeBounded`。

关键区别：检测预算不是整个业务请求的截止时间；请求中断不是强杀线程；审计允许记录不是业务执行成功记录。

`FailClosedTransformer` 在转换失败时返回不能定义成类的字节，触发类定义失败，并标记后续保护调用拒绝。此处要连同测试一起理解，不能随意改成“记录异常后返回原字节”。

## 第 7 步：先学身份作用域，再学 future

### 7.1 身份快照

阅读 `SecurityContext → SecurityContexts.open/restore → Scope.close → wrap/executor`，对应 `SecurityContextsTest`。

画出一个线程的身份变化：

```text
原身份 A → open(B) → 临时身份 B → close → 恢复 A
```

再观察 `restore(null)`：它清除当前工作线程的环境身份，结束后恢复旧值，而不是偷偷借用该线程原有权限。`authenticated` 只是快照工厂，真正的认证由业务完成。

### 7.2 异步拦截

阅读 `FutureAdvice.enter/exit → Bridge.guardFuture`，并运行：

```bash
bash scripts/demo.sh async-tool
bash scripts/demo.sh async-allowed
```

沿着两条路径分别追：

- 输入拒绝：Advice 保存异常、跳过原方法，退出逻辑返回失败 future。
- 输入允许：保存上下文；返回包装 future；源 future 完成后恢复身份，检查输出，再完成包装 future。

同时找取消传播的位置。返回 future 不代表结果已经检查，业务只能从受保护的包装 future 接收结果。

**练习：**结合 `stream/ContextPropagationTest` 和 Boot 的 `ContextIT`，跟一次工作线程本来有另一身份的完成回调，说明回调后为什么不会污染该线程。不要假设任意 `thenApplyAsync` 自动传播上下文，未覆盖路径见 [可信上下文](security-context.md)。

## 第 8 步：学习参数策略，把文本规则升级为结构化判断

阅读顺序：

1. `config/tool-policy-example.json`，先理解规则想约束什么。
2. `ToolPolicy.fromPath` 及规则构建入口。
3. `StrictJson`：重复键、非法格式、深度／大小限制。
4. `ToolPolicy.compile`：配置如何变成内部 Rule。
5. `ToolPolicy.evaluate`：工具名准入、参数解析、规则匹配和上下文约束。
6. `ToolPolicyTest`、`ContextToolPolicyTest`。

对照运行：

```bash
bash scripts/demo.sh tool-args-allowed config/tool-demo.properties
bash scripts/demo.sh tool-args-foreign config/tool-demo.properties
```

观察第二条命令的工具调用计数应为零。思考：字符串中的 JSON 转义是否改变真实客户 ID？参数中声称属于某租户，为什么不等于调用者真属于该租户？

完整规则格式见 [工具策略](tool-policy.md)。第一次不要扩展规则语言，先通过一个已有的允许／拒绝案例。

## 第 9 步：流式保护分两次学

流式比同步复杂，因为内容可能在最终响应到来前泄露。先学回调，再学 Flow，别一次读完所有状态。

### 9.1 回调式流

阅读 `StreamInputAdvice → GuardedStream.wrap → invoke/invokeInContext → buffer → 完成检查与回放`，搭配 `GuardedStreamTest`。

记录这几个变量的含义：`pending` 保存待交付回调，`channels` 拼接内容，`terminal` 控制终止，`deadline` 管理超时。继续查 `finishLocked`、`timeout`、`cancel`、`notifyError`，看异常时如何清理和通知。

学习目标是解释：为什么最终响应安全还不够？为什么要检查跨片段内容？为什么使用全量缓冲会改变首字延迟？

### 9.2 Flow／reactive

阅读 `ReactiveAdvice → Bridge.guardPublisher → ContextPublisher → GuardedPublisher.subscribe → Session`。

不要从第一行逐行硬读，按信号顺序跟：

```text
subscribe
  → 下游拿到 Subscription
  → start / 上游订阅
  → onNext 缓冲
  → onComplete 检查完整结果
  → 校验通过且下游 request(n) 有额度时 drain 交付
  → 完成或失败，释放资源
```

这只是正常路径；取消、错误、超时可以在中途发生。继续查 `Session.request/cancel/fail/timeout/drain/release` 与 `StreamRuntime`。

优先读 `GuardedPublisherTest`：

- `releaseRequiresBothValidationAndDownstreamDemand`：检查通过和下游需求缺一不可。
- `splitTextAndThinkingCannotHideBehindSafeFinalResponse`：不能仅检查最终汇总。
- `cancellationInOnSubscribeDoesNotStartUpstream`：订阅即取消不能触发上游副作用。
- `noDemandTimesOutAndCapacityIncludesCompletedUndeliveredStreams`：没有消费者需求也不能无限占容量。

最后再读 `ReactiveContent` 与 `RawStreamControl` 的事件适配。它们适配已支持的事件形式，不表示任意 provider 的事件都受支持，也不表示完成了全套 Reactive Streams TCK 验收。

## 第 10 步：用同一套思路理解 RAG 和 Memory

| 路径 | 阅读顺序 | 重点问题 |
| --- | --- | --- |
| RAG | `RagSyncAdvice`／`RagFutureAdvice` → `RagBridge.before/after` → 注册／构造 Advice → `RagBridgeTest`、`RagIT` | 检索前如何授权？检索结果怎样整批检查？lambda 在哪里被包装？ |
| Memory | `MemoryWriteAdvice`／`MemoryReadAdvice`／`MemoryFutureAdvice` → `MemoryBridge.before/after` → 分发／注册 Advice → `MemoryBridgeTest`、`MemoryIT` | 会话资源从哪来？为什么写入前要先快照整批消息？ |

先跑 RAG 的三个普通 demo：

```bash
bash scripts/demo.sh rag-input
bash scripts/demo.sh rag-output
bash scripts/demo.sh rag-allowed
```

观察 `RETRIEVAL_CALLS` 与 `modelCalls`：输入拒绝时应还没检索；结果拒绝时检索已经发生，但模型不应接收到内容。

Memory 没有同样的普通 demo 场景，可从 `integration-spring-boot` 的 `MemoryFixture` 和 `MemoryIT` 入手。把 `ResourceRef` 理解成“请求访问的资源”，再看 `FixtureDetector` 如何独立校验归属。会话 ID 不是用户身份；SDK 的整批检查也不是数据库事务。

覆盖与未覆盖路径必须对照 [RAG 安全](rag-security.md) 和 [Memory 安全](memory-security.md)，尤其是绕过框架接口、未注册代理／lambda 和直接数据库调用。

## 第 11 步：学会用测试定位问题

| 问题发生在哪 | 优先看哪里 |
| --- | --- |
| 策略结果不对、拒绝被覆盖、审计异常 | core 的单元测试 |
| JSON 参数、权限或身份字段绑定不对 | policy 的单元测试 |
| 流取消、背压、身份恢复、批量快照不对 | javaagent 下 bridge／stream 单元测试 |
| 普通应用里 Agent 没拦住 | `demo/src/test/java/io/agentsecurity/demo/AgentIT.java` |
| Boot 类加载、SPI、真实 HTTP/SSE 客户端问题 | `integration-spring-boot` 中的 `BootIT`、`ContextIT`、`RagIT`、`MemoryIT` |

按需运行，避免每次阅读都启动全量集成测试：

```bash
# 仅 Agent 的一个单元测试类；上游模块没有这个类时不报错。
mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 \
  -pl agent-security-javaagent -am \
  -Dtest=GuardedPublisherTest -Dsurefire.failIfNoSpecifiedTests=false test

# 完整验证：包含真实独立 JVM、普通 Java 和 Boot 集成场景。
bash scripts/verify.sh

# 交付验证：另外生成 SBOM、隔离重建并比对运行时 JAR。
bash scripts/release.sh
```

`mvn test` 不等于完整集成验证；`*IT` 由 Failsafe 在 `integration-test/verify` 阶段运行。测试会启动子 JVM，IDE 调试父测试进程不等于调试到子进程；初学时优先用第 4 步的单独 demo 调试命令。

注意 `-DskipTests` 构建只能得到可运行产物，不能作为修改后的回归通过证明。

## 第 12 步：做三个小练习，再考虑大改动

在自己的学习分支中依次尝试：

1. **只改配置：**复制演示配置到本地临时文件，新增一个工具拒绝规则，观察工具计数。练习区分配置问题和插桩问题。
2. **只写插件：**完成扩展指南中的订单 Detector；验证缺身份、缺权限、合法调用及 SPI 漏打包。练习区分策略发现和策略执行。
3. **补一个回归场景：**选择自己业务真正使用的异步或工具入口，先证明它经过保护边界，再断言拒绝时副作用计数为零。练习用行为证据代替“日志看起来正常”。

最后尝试口头解释下面五件事；解释不清时回到对应步骤：

- 为什么业务无需在每个工具中调用 SDK？
- 为什么只检测模型输入不能阻止所有危险工具调用？
- 为什么检测器超时后还需要固定线程数和队列上限？
- 为什么线程池复用时要恢复原身份，而不仅是设置新身份？
- 为什么流式结果必须在确认可交付后才调用业务消费者？

## 常见阅读误区

- 把 `SecurityAgent` 当业务入口：它只安装基础设施，每次调用主要跟 Bridge 和引擎。
- 把所有公开 Agent 类当成扩展 API：很多 public 是为插桩代码可见性服务，业务扩展入口见 [SDK 扩展指南](sdk-extension.md)。
- 一上来逐行读完整 `AgentInstrumentation`：先锁定一条同步工具路径，其他匹配按后续专题阅读。
- 把输出拒绝当作撤销副作用：工具输出检查时，工具可能已经修改外部系统。
- 把审计当执行结果、把 `runId` 当工具调用幂等键：它们都不提供这些语义。
- 把全部测试通过当成任意框架版本和路径都兼容：适配仍有固定版本与覆盖范围。

## 第一轮建议阅读清单

如果今天只准备跟通一条路径，照这个顺序即可：

```text
Demo.main(tool)
  → CustomerTools.sendEmail
  → config/demo.properties
  → SecurityEvent / Decision / Detector
  → PolicyEngine.check / LocalPolicy.evaluate
  → PolicyEngineTest
  → SecurityAgent.premain / AgentBootstrap.initialize
  → AgentInstrumentation.install 中的 toolType、toolMethod、SyncAdvice 绑定
  → SyncAdvice.enter / Bridge.before
  → 回到 sendEmail 断点，确认拒绝时不执行
```

读完后再进入 SPI、身份、future 和流式专题。修改前先看 [开发规范](development.md)，部署前再看 [运行手册](operations.md) 与 [生产验收清单](production-readiness.md)。
