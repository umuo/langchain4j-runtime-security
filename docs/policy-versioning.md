# 策略版本、原子发布与回滚

本轮提供进程内的版本化策略源。先编译候选，再发布完整快照；校验失败、发布冲突、版本重用或容量超限都不会替换当前有效策略。不依赖 Spring，不自动监听文件，不创建管理 HTTP 端点。

## 1. 先编译，再创建发布器

使用 `agent-security-policy` 模块的 PolicyCompiler 编译本地 Properties 与可选工具 JSON：

```java
import io.agentsecurity.core.PolicyEngine;
import io.agentsecurity.core.versioning.AtomicPolicy;
import io.agentsecurity.policy.versioning.PolicyCompiler;
import java.util.List;
import java.util.Properties;

var local = new Properties();
local.setProperty("deny.tools", "deleteAll");
local.setProperty("deny.text", "INJECTION_TEST_MARKER");

var initial = PolicyCompiler.compile("orders-v1", local, null);
var policies = new AtomicPolicy(initial, 16);
var engine = new PolicyEngine(List.of(policies), auditSink);
```

第三个参数是工具规则 JSON 文本，可传与 ToolPolicy.fromJson 相同的配置。null 表示没有附加工具 JSON，不表示跳过本地规则。local 和工具规则同时生效，任一拒绝即拒绝。

编译器不保留调用方的 Properties，之后修改原对象不会改变已编译规则。构建期间不要并发修改输入。约束为：最多 32 个属性、键最长 128 字符、单值最长 8192 字符、本地属性总计最多 65536 字符、工具 JSON 最多 1048576 字符；工具规则自身的节点、类型和深度限制仍生效。拒绝异常 UTF-16 代理字符，使用严格 UTF-8 计算摘要。

SHA-256 对属性按键排序、加域标识和长度前缀后计算，包含是否提供工具 JSON及其原始文本，不包含版本名。因此属性插入顺序不会影响摘要；工具 JSON 的空白变化会影响摘要。摘要标识本轮编译输入，不是签名，也不是跨 SDK 版本的行为一致性证明。

编译器当前只编译 LocalPolicy + ToolPolicy，不解析远程检测器、业务插件或凭据配置。其他固定检测器可继续放在同一检测链中。

## 2. 原子发布

```java
long expected = policies.state().generation();

var replacement = new Properties();
replacement.setProperty("deny.tools", "deleteAll,sendEmail");
var candidate = PolicyCompiler.compile("orders-v2", replacement, null);

var published = policies.publish(expected, candidate);
System.out.println(published.generation());
System.out.println(published.version());
System.out.println(published.sha256());
```

建议在编译前取得 expectedGeneration，避免编译期间别的管理员发布后，被当前操作无意覆盖。发布流程：

1. 候选先完整编译；失败不调用 publish。
2. 发布时确认 expectedGeneration 与当前值相同，否则拒绝过期请求。
3. 同版本名已登记不同摘要时拒绝，禁止把 `orders-v1` 改成另一套规则。
4. 新版本占用目录容量；容量满则拒绝，不自动淘汰回滚目标。
5. 一次 volatile 状态替换同时发布新版本和递增序号；检查线程无需等待管理锁。

初始 generation 为 1，每次成功 publish 或 rollback 都递增，包括再次发布相同版本。版本目录容量范围为 1～256；按实际规则大小选择容量，示例为 16。`policies.versions()` 返回不可修改的版本名列表，`policies.state()` 返回序号、版本和摘要，不暴露规则正文。

同版本同摘要再次发布时复用已登记的编译结果。不要把不可信请求直接转换为 PolicyRevision：手动构造自定义 detector 时，其不可变性、摘要真实性及资源生命周期由可信宿主负责；推荐使用 PolicyCompiler。

## 3. 回滚与并发保护

```java
var beforeRollback = policies.state();
var restored = policies.rollback(beforeRollback.generation(), "orders-v1");
```

只能回滚到当前实例已经登记的版本。回滚会生成新的 generation，而不会退回旧序号。例如 v1/1 → v2/2 → v1/3；持有 generation=1 的旧请求仍不能覆盖当前状态，避免版本名称相同造成的 ABA 问题。

generation 是当前实例内的乐观并发控制，不是认证凭据、跨实例租约或全局发布序号。状态和版本目录都在内存中，重启后从宿主提供的初始版本重新开始。生产管理层需要保存审批结果、策略制品和期望版本，并负责重启恢复、跨节点一致性及管理操作审计。

## 4. 检查与任务的一致性

引擎最多允许一个 VersionedDetector 策略源，避免无法唯一归属审计版本。每次 check 在检测总预算内取得一次快照，随后即使发布了新策略，也继续使用旧快照完成本次检查。前置委托检查和最终委托有效性复查仍然执行，版本固定不会绕过撤销、过期或身份校验。

取得快照与执行策略共享 DetectionLimits 的同一截止时间，快照读取异常或超时仍拒绝。内置 AtomicPolicy 的 snapshot 仅读取已发布状态；自定义 SPI 的 snapshot 必须线程安全，不应执行远程加载、认证或按线程上下文切换租户。

需要一个任务内多次检查使用同一版本时：

```java
try (var taskEngine = engine.pinPolicy()) {
    taskEngine.check(modelInputEvent);
    // 运行模型或调度子任务。
    taskEngine.check(toolInputEvent);
    // 只有检查通过才执行副作用。
}
```

显式将 taskEngine 传给后续异步任务或子 Agent，不能在任务中重新取得当前全局引擎代替它。此视图只固定版本化策略源，其他业务插件必须自己保证稳定性；它不固定身份、委托期限或权限，也不使已经撤销的操作重新有效。

视图共享原引擎的检测池和审计。关闭视图不会关闭原引擎，关闭原引擎后视图也拒绝执行。宿主需等待任务完成后再关闭拥有者。

**默认一致性范围是一次 check，不是整个模型调用或整个 run。** Java Agent 一次业务调用可能经过多个检查边界；更新发生在边界之间时，默认可使用不同版本。本轮尚未实现 Java Agent 自动按 runId 固定版本及跨任意异步边界传播。紧急策略发布也不会自动撤销已经固定旧版本的 SDK 任务，应结合现有 AgentRuntime 撤销机制管理。

## 5. Java Agent SPI 接入

应用的插件实现 VersionedDetector（它也是 Detector），返回项目共享 AtomicPolicy 的快照：

```java
package com.example.security;

public final class ProjectPolicyDetector
        implements io.agentsecurity.core.versioning.VersionedDetector {
    public ProjectPolicyDetector() {}

    @Override
    public io.agentsecurity.core.versioning.PolicyRevision snapshot() {
        return ProjectPolicies.shared().snapshot();
    }
}
```

ProjectPolicies 是应用自行实现的可信配置持有者，shared() 必须返回同一个发布器；不要在每次 snapshot 或每个 SPI 包装实例中重新建立版本目录。管理线程向该共享发布器 publish/rollback，即可影响后续检查，无需重新加载 SPI 类。

在应用 JAR 的 `META-INF/services/io.agentsecurity.core.Detector` 中填写：

```text
com.example.security.ProjectPolicyDetector
```

一次检测链只能有一个这样的插件。不能再给引擎同时追加第二个 VersionedDetector；多个静态 Detector 仍可组合。包装类必须直接实现 VersionedDetector，若只以普通 Detector 的 evaluate 转发，引擎无法识别快照契约并不会自动提供本节的一致性保证。

真实独立 JVM 示例见 demo 测试代码 VersionedApplication / VersionedAgentIT：同一进程中 v1 放行 → v2 阻断 → 回滚 v1 放行，底层模型执行次数为 2。policy 依赖只加在 demo 的 test scope，原普通 Java demo JAR 仍不包含 SDK。

## 6. 决策版本与安全审计

Decision 新增可空的 policyVersion，保留 `Decision(boolean, String)` 两参数构造以及 allow()/deny()。版本化引擎把选定版本写进最终 Decision；后续固定检测器拒绝或最终委托复查拒绝也不会丢掉已选定的版本。

FileAuditSink 及 Java Agent stderr 审计优先使用该决策版本；非版本化引擎沿用原静态 policy.version。JSONL 仍是 schema 3，policyVersion 字段类型不变；使用 record 反射/自定义序列化的消费者需要适配新增的 Decision 组件，并统一升级 SDK 模块版本。

不能取得快照时版本为保留标识 `unresolved`，包括快照异常/超时、引擎已关闭或前置委托已拒绝。它不伪装成某个已成功加载的版本；PolicyRevision 不允许使用 unresolved 作为业务版本名。

这里的版本表示**当前可变策略源选定的版本**，不是整个检测链的联合摘要。静态本地规则、其他 SPI、远程服务的策略版本及 AgentRuntime 生命周期审计不自动跟随它更新。OTLP 遥测当前也未增加该版本属性；要追溯决策版本，应读取可靠安全审计。多个项目汇总日志时请使用带项目命名空间的唯一版本名。

管理 API 不提供登录认证、签名校验、审批流或管理变更的持久化日志。发布入口必须由可信宿主鉴权，不能暴露给模型工具作为任意参数操作；检测日志也不能代替管理员操作审计。

## 7. 本轮验收

新增测试覆盖：

- 两个管理员持相同 generation 并发发布，只允许一个成功。
- 无效规则、错误版本复用、过期发布、目录满和未知回滚目标不改变有效状态。
- 在途检查仍按旧快照完成，下一次检查采用新版本；显式固定视图仍使用旧版本。
- 最终 JSONL 文件中的允许/拒绝记录对应选定版本，策略正文不进入日志。
- 快照故障记为 unresolved 并拒绝，关闭原引擎后固定视图不能继续放行。
- 真实 Java Agent SPI 在同进程发布/回滚生效，拒绝时模型没有副作用。

本轮不代表跨节点发布、持久化恢复、签名和审批、自动按 run 固定、长期压力或策略语义效果已验收。


本轮执行结果：2026-09-28，完整发布验证 356 项测试零失败，四个运行时 JAR 隔离重建一致；模块明细见 [生产验收记录](production-readiness.md)。新增 8 项核心/编译器测试及 1 项真实 SPI 独立 JVM 测试。源代码按 Java 17 编译，本机运行 JDK 21.0.4，未把本机结果当作远端 CI 已通过。
