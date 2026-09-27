# SDK 扩展指南：为业务项目编写专属安全策略

多 Agent 的父子身份、权限收窄和生命周期接入见 [多 Agent 安全](multi-agent-security.md)。

本文面向已有 LangChain4j 项目的开发者，说明当前仓库实际提供哪些扩展能力，以及如何把项目专属策略打成 JAR 并接入应用。示例基于 `0.1.0-SNAPSHOT`，Agent 固定适配 LangChain4j **1.20.0**；SDK、Agent、策略插件应使用同一份构建产物，不能仅凭相同的 SNAPSHOT 版本号判断兼容。

**最常用的方式：实现 `Detector` → 注册 Java SPI → 把策略 JAR 加入应用依赖 → 使用 `-javaagent` 启动。** 普通 Java 和 Spring Boot 均可使用。涉及用户／租户权限时，再在认证入口提供可信身份。

## 1. 先选扩展方式

| 需求 | 扩展入口 | 是否能被现有 Agent 自动使用 | 你需要完成的工作 |
| --- | --- | --- | --- |
| 限制工具名称、文本、参数结构、权限 | properties 与工具 JSON 策略 | 是 | 编写配置，不必开发插件 |
| 实现业务授权、内容检测、数据归属判断 | `Detector.evaluate(SecurityEvent)` + Java SPI | 是 | 开发并部署策略 JAR |
| 调用企业内部风控／内容检测服务 | 自定义 `Detector` | 是 | 自行实现客户端、协议校验、超时和连接资源管理 |
| 提供用户、租户、权限及请求关联信息 | `SecurityContext`、`SecurityContexts` | 已适配边界会使用这些信息 | 在可信认证入口建立作用域；补齐业务异步传播 |
| 手动保护其他业务操作，或使用 Spring Bean 构造策略 | `PolicyEngine` | 不自动接管手动创建的引擎 | 在业务副作用发生前显式调用 `check` |
| 将审计写入自己的日志／事件系统 | `BiConsumer<SecurityEvent, Decision>`，可包装 `BoundedAuditSink` | **Agent 暂无自定义审计 SPI** | 独立构造 `PolicyEngine` 时传入审计实现 |
| 拦截新的框架方法、其他 LangChain4j 版本或 MCP | Agent 插桩、Advice、Bridge | 没有通用适配器 SPI | 修改 Agent 实现并增加真实 JVM 集成验证 |

`Detector` 只返回允许／拒绝，不能修改 prompt、工具参数、输出或路由到另一个模型；也没有审批挂起、策略优先级、自动重试、动态卸载插件的接口。需要脱敏改写时，应在应用层实现，不能把返回 `allow()` 当成“已改写”。

## 2. 检测器能做什么

| 业务功能 | 推荐检查位置 | 实现要点 |
| --- | --- | --- |
| 禁止删除、退款等高风险工具 | `TOOL_INPUT` | 比较工具名，结合可信权限判断；拒绝时受保护方法不执行 |
| 金额／收件人／客户 ID 限制 | `TOOL_INPUT` | 使用内置工具 JSON 规则，或严格解析参数并查询业务授权数据 |
| 企业敏感信息、提示注入内容检测 | 模型、工具、检索及记忆的相应输入／输出阶段 | 检测算法／外部服务由插件实现；SDK 本身不保证识别所有攻击 |
| 限制知识库读取权限 | `RETRIEVAL_INPUT` | 依据可信上下文与组件标签授权；真实数据源仍需执行 ACL |
| 阻止检索内容污染模型 | `RETRIEVAL_OUTPUT`、`AUGMENTATION_OUTPUT` | 对整批文本和已提取的元数据检测；拒绝整批交付 |
| 隔离租户的历史会话 | Memory 四类阶段 | 使用 `resource` 与可信身份查询会话归属 |
| 接入内部风险评分／规则中心 | 任意适用阶段 | 将服务响应映射为 `Decision`；失败不返回允许 |

输出检测发生时，上游模型请求、检索或工具执行可能已经发生。比如 `TOOL_OUTPUT` 拒绝不能撤销转账，`RETRIEVAL_OUTPUT` 拒绝不能撤销数据读取。应把授权放在输入阶段，输出阶段用于阻止结果继续传播。

## 3. 最小完整插件：订单工具权限

下面示例禁止 `deleteAllOrders`；调用 `refundOrder` 必须具有 `order:refund` 权限。工具名必须与目标应用实际暴露给 LangChain4j 的名称一致。

### 3.1 先准备 SDK 依赖

以下流程从源码安装 SDK 到仓库自带 Maven 缓存，不假设制品已发布到公共仓库。在本仓库根目录执行：

```bash
# 记录绝对路径，后续插件构建也使用这份本地仓库。
export AGENT_SECURITY_M2="$PWD/.cache/m2"
mvn -B -ntp -s .mvn/settings.xml \
  -Dmaven.repo.local="$AGENT_SECURITY_M2" \
  -pl agent-security-core -am -DskipTests install
```

团队使用时可将同一构建版本发布到私有 Maven 仓库，并配置业务项目的 Maven settings。Agent JAR 单独通过本仓库的发布流程构建，详见 [构建与发布工程](release-engineering.md)。

### 3.2 创建独立 Maven 项目

```text
order-agent-security/
├── pom.xml
└── src/main/
    ├── java/com/example/security/
    │   ├── OrderSecurityDetector.java
    │   └── PluginSmoke.java
    └── resources/META-INF/services/
        └── io.agentsecurity.core.Detector
```

`PluginSmoke` 是无外部服务的自检入口，可随示例一起保留；实际业务可以移到测试模块。

`pom.xml`：

```xml
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>order-agent-security</artifactId>
  <version>1.0.0</version>
  <properties>
    <maven.compiler.release>17</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>io.agentsecurity</groupId>
      <artifactId>agent-security-core</artifactId>
      <version>0.1.0-SNAPSHOT</version>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.16.0</version>
      </plugin>
    </plugins>
  </build>
</project>
```

### 3.3 实现检测器

`src/main/java/com/example/security/OrderSecurityDetector.java`：

```java
package com.example.security;

import io.agentsecurity.core.Decision;
import io.agentsecurity.core.Detector;
import io.agentsecurity.core.SecurityEvent;

/** 订单项目的工具授权策略；不保存请求状态，不执行订单修改。 */
public final class OrderSecurityDetector implements Detector {

    public OrderSecurityDetector() {}

    @Override
    public Decision evaluate(SecurityEvent event) {
        // 只处理自己负责的阶段，其他阶段交给检测链中的其他策略。
        if (event.phase() != SecurityEvent.Phase.TOOL_INPUT) {
            return Decision.allow();
        }
        if ("deleteAllOrders".equals(event.operation())) {
            return Decision.deny("order-bulk-delete-denied");
        }
        if ("refundOrder".equals(event.operation())) {
            var context = event.context();
            if (context == null) {
                return Decision.deny("order-context-required");
            }
            if (!context.permissions().contains("order:refund")) {
                return Decision.deny("order-refund-forbidden");
            }
        }
        return Decision.allow();
    }
}
```

这只是两个工具的示例规则，**不是完整工具白名单，也没有校验退款金额和订单归属**。其他工具会被本检测器允许，仍需其他策略决定能否执行。参数校验和身份绑定见 [工具策略](tool-policy.md) 与 [可信上下文](security-context.md)。

### 3.4 注册 Java SPI

创建 UTF-8 文件 `src/main/resources/META-INF/services/io.agentsecurity.core.Detector`，内容为实现类全名：

```text
com.example.security.OrderSecurityDetector
```

多个检测器可以逐行列出。文件名没有 `.txt` 后缀；不能只给类加 Spring `@Component` 而不注册 SPI。

### 3.5 添加自检入口

`src/main/java/com/example/security/PluginSmoke.java`：

```java
package com.example.security;

import io.agentsecurity.core.Detector;
import io.agentsecurity.core.PolicyEngine;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import io.agentsecurity.core.SecurityEvent;
import java.util.ServiceLoader;
import java.util.Set;

/** 验证 SPI 打包、缺少身份时拒绝、权限不足时拒绝及合法放行。 */
public final class PluginSmoke {

    public static void main(String[] args) {
        var detectors = ServiceLoader.load(Detector.class).stream()
                .map(ServiceLoader.Provider::get).toList();
        if (detectors.stream().noneMatch(OrderSecurityDetector.class::isInstance)) {
            throw new AssertionError("OrderSecurityDetector 未被 SPI 发现");
        }
        // 无操作审计仅用于这个自检；业务环境应传入真实审计实现。
        try (var engine = new PolicyEngine(detectors, (event, decision) -> {})) {
            expectBlocked(engine, "deleteAllOrders", "order-bulk-delete-denied");
            expectBlocked(engine, "refundOrder", "order-context-required");
            var reader = SecurityContext.authenticated("tenant-a", "user-a", Set.of());
            try (var scope = SecurityContexts.open(reader)) {
                expectBlocked(engine, "refundOrder", "order-refund-forbidden");
            }
            var operator = SecurityContext.authenticated(
                    "tenant-a", "user-a", Set.of("order:refund"));
            try (var scope = SecurityContexts.open(operator)) {
                engine.check(event("refundOrder"));
            }
        }
        System.out.println("PLUGIN_SMOKE_OK");
    }

    private static SecurityEvent event(String tool) {
        return new SecurityEvent(SecurityEvent.Phase.TOOL_INPUT, tool, "{}");
    }

    private static void expectBlocked(PolicyEngine engine, String tool, String rule) {
        try {
            engine.check(event(tool));
        } catch (SecurityBlockedException blocked) {
            if (!rule.equals(blocked.ruleId())) {
                throw new AssertionError("错误的阻断原因", blocked);
            }
            return;
        }
        throw new AssertionError("本应阻断: " + tool);
    }
}
```

在插件项目根目录执行（沿用 3.1 设置的绝对路径变量）：

```bash
mvn -Dmaven.repo.local="$AGENT_SECURITY_M2" clean install

# 下例是 macOS/Linux 的 classpath 分隔符；Windows 使用分号。
java -cp "target/order-agent-security-1.0.0.jar:$AGENT_SECURITY_M2/io/agentsecurity/agent-security-core/0.1.0-SNAPSHOT/agent-security-core-0.1.0-SNAPSHOT.jar" \
  com.example.security.PluginSmoke

# 检查最终 JAR 确实包含 SPI 文件和实现类。
jar tf target/order-agent-security-1.0.0.jar
```

预期打印 `PLUGIN_SMOKE_OK`。这验证插件本身，不代表目标应用的 Agent 插桩路径已覆盖；仍需第 9 节的业务集成验证。

## 4. 接入已有 LangChain4j 应用

### 4.1 添加策略插件依赖

业务项目添加下列依赖，使用同一个 Maven 本地缓存或团队私有仓库。SDK core 会作为插件的传递依赖进入应用；主动调用身份 API 的业务模块也可以直接声明 core 依赖。

```xml
<dependency>
  <groupId>com.example</groupId>
  <artifactId>order-agent-security</artifactId>
  <version>1.0.0</version>
</dependency>
```

业务应用不用依赖 `agent-security-javaagent` Maven 模块；其完整 JAR 通过 JVM 参数加载。不要将 `io.agentsecurity.core` 重定位到另一包名或混入不兼容版本，否则 SPI 类型和上下文可能不一致。

### 4.2 编写 Agent 配置

`/opt/security/order-policy.properties` 最小示例：

```properties
max.text.chars=100000
detector.timeout.millis=500
detector.max.concurrent=4
policy.version=order-v1
context.required=false
```

此示例只要求退款工具具有身份。若希望所有进入策略引擎的受保护事件都要求身份，先完成认证接入，再设置 `context.required=true`。未配置 `audit.path` 时使用内置 stderr 审计；部署配置见 [运行手册](operations.md)。

Agent 会校验支持的配置键。**没有通用“把 properties 注入插件”的接口**，不要把 `order.xxx` 直接塞进这个文件。插件自己的配置应使用独立文件、环境变量或 `-Dorder.security.config=/path/...` 等由插件明确读取的来源。构造器保持轻量，避免在加载时进行耗时远程初始化。

### 4.3 启动应用

Spring Boot 可执行 JAR：插件依赖随应用打进 `BOOT-INF/lib`，启动方式为：

```bash
java \
  -javaagent:/opt/security/agent-security-javaagent.jar=/opt/security/order-policy.properties \
  -jar /opt/app/application.jar
```

普通 Java 薄 JAR：将应用依赖（包括策略 JAR 和 core）放进 `/opt/app/lib`：

```bash
java \
  -javaagent:/opt/security/agent-security-javaagent.jar=/opt/security/order-policy.properties \
  -cp "/opt/app/application.jar:/opt/app/lib/*" \
  com.example.Application
```

普通可执行 fat JAR 可用 `-jar`，但打包时必须合并 `META-INF/services` 文件；使用 Maven Shade 时可配置 `ServicesResourceTransformer`。不能依赖 `java -cp plugin.jar -jar application.jar` 把插件加入可执行 JAR 的搜索路径。仅把 JAR 放在 Agent 同目录也不会自动加载。

Agent 必须早于会加载 LangChain4j 的其他 Agent。当前没有启动后 attach、策略 JAR 热加载／热卸载支持；更新插件按重启应用处理。自定义隔离 ClassLoader、JPMS 和 native image 不在当前已验证范围内。

### 4.4 接入可信身份

以下是认证入口片段，变量由目标应用已有认证系统提供：

```java
var context = SecurityContext.authenticated(
        authenticatedTenantId, authenticatedUserId, verifiedPermissions);
try (var scope = SecurityContexts.open(context)) {
    return assistant.chat(userMessage);
}
```

需要导入 `io.agentsecurity.core.SecurityContext` 和 `SecurityContexts`。`authenticated(...)` 只是创建快照，不验证凭证。不要从 prompt、模型生成的工具参数或未验证 header 构造身份。作用域退出后自动恢复原身份。

业务自建线程池通过 `SecurityContexts.executor(applicationExecutor)`、`executorService(...)` 或 `wrap(...)` 传播快照；Agent 不自动接管所有线程和 Reactor Context。完整示例见 [身份与异步传播](security-context.md)。

## 5. SecurityEvent 字段和检查时机

### 5.1 字段含义

| 字段 | 含义 | 开发约束 |
| --- | --- | --- |
| `id()` | 本次检测事件 UUID | 不是唯一业务调用 ID；多个保护层可产生多个事件 |
| `phase()` | 当前检查阶段 | 必须先判断阶段，再解释 `operation` 和 `text` |
| `operation()` | 工具名或框架组件标签等 | 不是统一 URL、资源 ID，也不是可信身份 |
| `text()` | 适配器提取的待检测文本 | 可能含敏感内容；不是完整框架对象或统一 JSON 信封；自行构造事件时可以为 null |
| `context()` | 可空的可信身份快照 | 包含 `runId`、tenantId、principalId、permissions，以及可空 invocation 委托句柄；由可信入口建立 |
| `resource()` | 可空的资源引用 | 当前自动适配主要用于 Memory；资源 ID 不证明资源归属 |

检测器优先使用 `event.context()`，不要假设请求的 ThreadLocal、Spring Security 上下文或数据库事务会被带入检测线程。不要直接记录 `text`、`resource.id`、身份或工具参数。

运行时另有 AGENT_START／AGENT_DELEGATE／AGENT_FINISH／AGENT_REVOKE 生命周期阶段，由 AgentRuntime 的审计消费者接收，不会自动送入应用 Detector 链。

### 5.2 各阶段可见内容

| `phase` | 检查时机 | `operation` / `text` 的当前语义 |
| --- | --- | --- |
| `MODEL_INPUT` | 模型调用前 | `chat`；已提取的消息文本，包括支持的历史消息内容 |
| `MODEL_OUTPUT` | 模型结果交付前 | `chat` 或 `stream`；模型结果文本或受保护流片段的检查文本 |
| `TOOL_INPUT` | 工具执行前 | 工具名；JSON 参数字符串 |
| `TOOL_OUTPUT` | 工具返回后、结果交付前 | 工具名；工具结果文本 |
| `RETRIEVAL_INPUT` | 检索前 | 检索组件标签；查询及已支持的消息元数据文本 |
| `RETRIEVAL_OUTPUT` | 检索完成、结果交付前 | 检索组件标签；整批内容及文档元数据文本 |
| `AUGMENTATION_INPUT` | 增强前 | 增强组件标签；输入消息及已支持的查询元数据文本 |
| `AUGMENTATION_OUTPUT` | 增强结果交付前 | 增强组件标签；增强消息和返回内容文本 |
| `MEMORY_READ_INPUT` | 历史读取前 | 实现类名加 `#方法名`；依赖 `resource` 授权，不从正文猜测会话 ID |
| `MEMORY_READ_OUTPUT` | 历史读取后、结果交付前 | 同上；历史消息批次文本 |
| `MEMORY_WRITE` | 写入前 | 同上；待写批次文本 |
| `MEMORY_DELETE` | 删除／清空前 | 同上；依赖 `resource` 授权 |

RAG 标签是实现类全名，隐藏 lambda 使用 `lambda:` 加宿主类名；不能据此区分同一实现类的不同数据源实例。RAG 文本是提取后的聚合表示，没有结构化的逐文档 ID、来源认证或独立 metadata map。Memory 的资源类型为 `memory:string`、`memory:uuid`、`memory:int`、`memory:long`。详细覆盖边界见 [RAG](rag-security.md) 和 [Memory](memory-security.md)。

流式输出当前先缓冲检查，再释放给业务；不是允许插件逐 token 修改内容。检测可能发生多次，不要假设每次模型调用只出现一个输出事件。

## 6. Detector 的执行、加载和失败约定

接口为 `Decision evaluate(SecurityEvent event)`，返回值只有 `allowed` 和 `ruleId`。

- `Decision.allow()`：当前策略通过，后续检测器仍可能拒绝。
- `Decision.deny("order-refund-forbidden")`：拒绝；规则 ID 只能是 1～80 位字母、数字、下划线、点或连字符，不能携带业务正文。
- 检测器抛异常或返回 null：通常转换为 `detector-error`。不要依赖在检测器内抛自定义异常来传递业务规则 ID，应直接返回 `Decision.deny(...)`。

Agent 先执行已配置的内置策略，再执行应用 SPI；任一拒绝就短路，后续检测器可能不会运行。全部允许且审计确认成功后才放行。**不要把审计、必须执行的监控、扣费、额度扣减或审批副作用放进 Detector。**

加载由 Bridge 使用边界对象所属类的 ClassLoader 调用 `ServiceLoader<Detector>`，并用 `ClassValue` 缓存组合后的引擎。同一插件可能被多次实例化；不能假设它是全 JVM 唯一单例，也不能依赖跨 JAR 的发现顺序。确需固定子规则顺序时，可以在一个 Detector 内自行组合无副作用的子规则。

SPI 文件完全缺失时，`ServiceLoader` 可以返回空列表，**不会因为“业务专属策略没有部署”自动拒绝**。因此必须验证插件发现，并在目标应用中执行一个预期拒绝的真实工具调用。服务声明损坏／构造失败等会拒绝，错误可能表现为 `detector-error`、`detector-load-error` 或超时等，取决于失败位置。

自定义检测器和 SPI 构造使用共享的有界线程池。默认每个事件检测链总预算 500 ms、最多 4 个执行线程及 4 个排队任务；链中每个检测器不会获得新的 500 ms。SPI 构造另外有一次同样预算。实例应线程安全，不将请求写入实例字段；检测器不应递归调用受保护的 Agent／模型，以免重入、线程耗尽或死锁。

超时会请求中断，但无法安全强杀忽略中断的插件；容量耗尽会继续拒绝。远程服务客户端必须自行设置连接、读取／请求超时、连接池和响应大小上限，不可只依赖外层预算。SPI 没有插件销毁回调，`Detector` 也没有 `close` 契约；长生命周期客户端资源需插件自行设计管理。

远程返回的非法格式、未知决策值、认证失败、超时和断路器打开都应拒绝，不能在 `catch` 中返回 allow。业务身份、正文发送范围由你与内部检测服务约定；内置日志脱敏不会替你脱敏网络请求。

## 7. 独立 SDK：自定义策略组合与审计

当你不需要 Agent 自动插桩，或要保护未适配的业务入口时，可显式创建 `PolicyEngine`。下面是方法体片段；`OrderSecurityDetector` 来自前文，其他类型来自 `io.agentsecurity.core`，另需导入 `java.time.Duration` 和 `java.util.List`。

```java
try (var audit = new BoundedAuditSink(
        (event, decision) -> {
            // 示例输出；生产实现应确认持久化成功，失败时抛异常。
            System.out.printf("event=%s phase=%s allowed=%s rule=%s%n",
                    event.id(), event.phase(), decision.allowed(), decision.ruleId());
            if (System.out.checkError()) {
                throw new IllegalStateException("Audit write failed");
            }
        }, Duration.ofSeconds(1), 128);
     var engine = new PolicyEngine(
        List.of(new OrderSecurityDetector()), audit,
        new DetectionLimits(Duration.ofMillis(500), 4))) {
    engine.check(new SecurityEvent(
            SecurityEvent.Phase.TOOL_INPUT, "deleteAllOrders", "{}"));
    // 只有 check 正常返回才可执行对应业务操作；本例会在上面被拒绝。
}
```

实际应用通常在组件初始化时创建引擎、在应用关闭时释放，而不是为每个请求创建线程池。裸 `BiConsumer` 在调用线程中执行，没有自动超时；需要隔离和资源限制时使用 `BoundedAuditSink`。该包装器在写入失败、超时或队列饱和后持续拒绝，直到重建实例。审计记录策略决策，不代表业务副作用已经成功。

`withAdditionalDetectors(...)` 返回共享执行器的新引擎视图，不修改原引擎；关闭原始拥有者引擎会影响派生引擎，关闭派生视图不关闭共享执行器。`PolicyEngine.close()` 不负责关闭任意传入的审计回调，应像示例一样管理审计生命周期。

Spring 应用可以用已注入业务服务的 Detector Bean 来构造这个手动引擎。**该引擎不会自动替换 Java Agent 内部引擎**；当前没有 Spring Bean 到 Agent SPI 的自动桥接。

## 8. 哪些需求需要继续开发 SDK／Agent

| 需求 | 当前状态与做法 |
| --- | --- |
| 在策略拒绝后修改请求再继续 | Decision 不支持改写；应用自行处理，或扩展 SDK 协议 |
| Agent 自动使用自定义审计实现 | 尚无审计 SPI；需扩展启动配置和审计装配 |
| 新的 event phase 或附加结构化字段 | 事件类型固定；需兼容性设计并调整 SDK 和 Agent |
| 任意新框架／MCP／不同 LangChain4j 版本自动拦截 | 没有公开的适配器注册 SPI；需增加 matcher、Advice、Bridge 及集成测试 |
| 运行中更新插件 JAR、动态 attach | 未实现；当前按应用重启部署 |
| 从策略中心自动拉取配置 | 未内置；Detector 可自行实现规则快照读取，但并发更新、失效与错误拒绝语义由插件负责 |
| 自动接入 Spring Security／Reactor／所有业务线程池 | 未实现；认证和未覆盖的异步边界由应用显式接入 |
| 精准关联 tool-call、去重、限额扣减、审批流 | 未提供完整协议；`runId` 只用于关联，不能当成一次工具调用的幂等键 |

`io.agentsecurity.agent.*` 中的公开类主要供插桩字节码调用，不作为业务插件扩展 API。插件应依赖 core，按需依赖 policy 模块，避免直接调用 Bridge 或修改 Agent 静态状态。

## 9. 接入验收与排错

在目标项目验证以下场景，不能只检查启动成功或 `instrumented=...` 日志：

| 验证场景 | 预期结果 |
| --- | --- |
| 独立运行 `PluginSmoke` | SPI 确实发现专属 Detector，输出成功标记 |
| 实际调用被禁止的工具 | 工具方法体的计数／测试存储写入次数为零 |
| 没有身份或权限 | 返回可识别拒绝原因，工具不执行 |
| 身份、权限和参数合法 | 实际工具能正常执行 |
| 检测器抛异常、超时、返回 null | 拒绝受保护操作，不回退到允许 |
| 两个不同租户并发及线程复用 | 不串用身份；按各自上下文判断 |
| 模型、工具或检索输出违规 | 结果不交付，但不要断言已发生的外部调用被撤销 |
| 应用使用 future／流式路径 | 在相应异步失败通道观察阻断，并验证业务消费者未拿到违规内容 |

同步拒绝通常抛 `SecurityBlockedException`；future 通过异常完成返回，调用方可能看到外层 `CompletionException`／`ExecutionException`，需要检查 cause；流式路径通过相应错误回调／信号交付。`ruleId()` 用于稳定业务分支，不要依赖异常消息文本。

| 问题 | 优先检查 |
| --- | --- |
| 应用启动了，但专属策略没执行 | SPI 文件是否漏打包、文件名是否错误、插件是否处于应用可见 classpath、该调用是否真的经过已支持拦截点 |
| 普通 JAR 可用，fat JAR 不生效 | 打包器是否覆盖了 `META-INF/services`；不要将插件只放在 Agent 旁边 |
| Detector 中注入的 Spring 服务为 null | SPI 使用无参构造，不由 Spring 管理；改为明确装配方案，不要假设注解自动生效 |
| `detector-error`／`detector-load-error` | 构造失败、依赖缺失、类型版本冲突、SPI 声明错误或 evaluate 异常；不要通过放行掩盖错误 |
| `detector-timeout`／`detector-capacity` | 总预算过短、远程调用阻塞、未响应中断、递归调用或并发量超过限制 |
| `missing-security-context` 或插件身份为空 | 作用域是否在调用前建立、是否正确关闭、业务自建异步边界是否传播身份 |
| `audit-error` | 审计写入／队列／超时异常，当前审计实例可能已进入持续拒绝状态 |
| 启动失败提示未知配置键 | 插件私有配置误放入 Agent properties；改用独立配置来源 |
| 某种框架调用没有事件 | 核对固定版本和适配范围；增加 Detector 不会自动创建新的插桩点 |

现有仓库测试覆盖应用侧 SPI 的拒绝、超时和异常，以及普通 Java／Boot 的真实 JVM 拦截路径。你的专属策略仍应增加自己的单元测试和真实业务调用验证。完整支持与未验收项目见 [生产验收清单](production-readiness.md)。
