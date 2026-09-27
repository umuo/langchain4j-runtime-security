# Agent Security Wiki

**Java AI Agent 运行时安全指南**

Agent Security 将独立安全 SDK 与 Java Agent 自动插桩结合，在 LangChain4j 的模型、工具、检索和会话记忆入口执行策略检查。

!!! warning "当前状态"
    项目适配固定 LangChain4j 1.20.0，仍处于生产化开发阶段。请先阅读[生产验收清单](production-readiness.md)及各模块的支持边界；Java Agent 不是 JVM 沙箱。

## 从这里开始

1. 阅读[项目概览与快速运行](overview.md)，运行无 Agent／启用 Agent 的对照演示。
2. 使用[工具策略](tool-policy.md)限制可执行工具和参数。
3. 需要用户或租户权限时，接入[可信身份上下文](security-context.md)。
4. 部署前检查[运行手册](operations.md)与[生产验收清单](production-readiness.md)。

## 按场景查阅

| 场景 | 文档 |
| --- | --- |
| 工具准入、参数校验、执行前拦截 | [工具权限与参数规则](tool-policy.md) |
| 身份认证结果接入、租户绑定、异步上下文 | [可信身份与异步传播](security-context.md) |
| 检索前授权、检索结果检查、数据源 ACL 边界 | [RAG 检索安全](rag-security.md) |
| 历史消息读写、删除授权、会话资源权限 | [Memory 会话安全](memory-security.md) |
| 部署配置、拒绝原因、审计与恢复 | [运行与故障恢复](operations.md) |
| CI、SBOM、交付证据、可重复构建 | [构建与发布工程](release-engineering.md) |
| 技术选型及原型设计背景 | [技术调研](langchain4j-runtime-security-spike.md) |

## 配置示例

- [基础演示策略](config/demo.properties)
- [结构化工具演示配置](config/tool-demo.properties)与[工具规则](config/tool-policy-example.json)
- [身份绑定工具规则](config/context-tool-policy-example.json)
- [部署配置示例](config/deployment-example.properties)

这些文件来自仓库的 `config/`，仅用于演示和配置参考。修改后应按运行手册完成真实应用验证。

## 维护文档

站点由 MkDocs Material 构建，支持中文搜索、目录导航和深浅色切换。见 [Wiki 维护指南](wiki-maintenance.md)。
