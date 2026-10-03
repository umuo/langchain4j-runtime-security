# LangChain4j 版本准入

Agent 默认构建使用 `langchain4j-core 1.20.0`，真实依赖回归覆盖 `1.20.0` 和 `1.21.0`。运行时不再要求版本字符串精确等于该基准，而是允许 `1.20.x`／`1.21.x` 正式补丁版本，并在首次受保护调用前检查关键 API 契约。

- `1.20.0`、`1.21.0` 及同系列补丁等正式版本进入 API 检查。
- 其他小版本、主版本、SNAPSHOT、beta、版本后缀及格式异常的版本拒绝，原因是 `unsupported-langchain4j-version`。
- 缺少 `langchain4j-core` 的 `pom.properties` 仍拒绝，原因是 `missing-version-metadata`。
- 关键类、公开实例方法、参数类型或返回类型不符合适配契约时拒绝，原因是 `incompatible-langchain4j-api`。检查不初始化依赖类、不执行业务方法，错误信息不包含依赖异常详情。

检查包括模型同步／异步／流式入口、请求与消息访问方法、工具请求、内存和 RAG 的关键接口。ClassLoader 能加载 AI Services 的 `ToolExecutor` 时，还检查工具执行器的同步／异步接口及结果访问方法；仅使用 core 的应用无需引入 AI Services。

版本和 API 检查全部成功后按 ClassLoader 弱引用缓存；失败不缓存。`AgentCoverage.SUPPORTED_LANGCHAIN4J` 保留为默认构建基准，`VERIFIED_LANGCHAIN4J` 列出真实依赖回归版本，`ACCEPTED_LANGCHAIN4J` 表示版本准入系列。诊断中的 `versionChecksPassed`／`versionChecksFailed` 统计这次组合检查，缓存命中不增加计数。

补丁版本准入及签名检查不等于完整兼容性证明：方法内部行为、新增调用路径、任意混用依赖、自定义加载器仍需要业务集成回归。本次测试使用 `1.21.0` 真实依赖运行完整回归，并对 `1.20.0` 复测模型、工具、RAG、Memory、MCP 入口及 Spring Boot 等相关用例，另通过替换版本元数据验证补丁准入，并模拟关键 API 缺失或签名变化；不宣称已对所有补丁版本实际制品完成验收。其他小版本需补充对应适配及真实依赖回归后再扩展准入。

MCP 的独立版本要求仍为 `1.20.0-beta30`，其传输和分页实现依赖专门适配。工具规则 `deny.tools` 仍在工具执行前检查。

在仓库根目录分别运行（两次构建必须顺序执行）：

```bash
mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 clean verify
mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 -Dlangchain4j.version=1.21.0 clean verify
```

CI 单独运行 `1.21.0` 的 JDK 21 兼容性任务，默认版本继续使用原有 JDK 矩阵。
