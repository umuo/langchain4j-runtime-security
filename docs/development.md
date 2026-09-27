# 开发规范与代码布局

Java 主代码和测试代码统一使用四空格缩进、UTF-8 和 LF 换行。Spotless 固定 Google Java Format 1.24.0 的 AOSP 风格；Checkstyle 要求控制语句带花括号、每行只写一条语句，并检查修饰符顺序。普通 `else if` 链保持标准写法。

## 职责划分

| 目录或包 | 职责 |
| --- | --- |
| `agent-security-core / io.agentsecurity.core` | 对外 SDK、检测器 SPI、策略执行、身份上下文和审计 |
| `core.telemetry` | 固定维度指标与有界脱敏关联队列，不依赖导出协议 |
| `agent-security-telemetry / io.agentsecurity.telemetry` | 可选 Prometheus 文本与 OTLP/HTTP 日志导出、协议和健康指标 |
| `core.delegation` | 同 JVM 的父子执行登记、权限收窄、有效性检查与生命周期 |
| `agent-security-policy / io.agentsecurity.policy` | 工具参数策略和严格 JSON 解析 |
| `agent-security-javaagent / io.agentsecurity.agent` | `premain` 入口与启动配置 |
| `agent.instrumentation` | Byte Buddy 匹配、注册及插桩失败处理 |
| `agent.instrumentation.advice` | 按模型、工具、RAG、记忆、异步上下文拆分的入口拦截器 |
| `agent.bridge` | 将框架对象转换为安全事件，连接 SDK 检测链 |
| `agent.stream` | 流式缓冲、背压、取消、超时和资源限额 |
| `demo` | 不依赖 Spring 的集成示例和测试 |
| `integration-spring-boot` | Spring Boot 集成验证夹具 |

对外 SDK 继续保留 `io.agentsecurity.core` 包，避免因内部整理而改变业务接入方式。`io.agentsecurity.agent` 及其子包属于 Agent 内部实现；部分桥接类型为插桩代码调用而公开，不作为业务 SDK API。紧密依赖外部对象状态的订阅状态机等可保留为内部类，独立职责应使用独立文件。测试与被测实现按包对应组织。

## 注释与安全约束

主要类型使用中文 Javadoc 解释职责；复杂方法、线程边界和安全分支应说明约束及原因，避免逐句翻译代码。重点说明检测失败时拒绝、共享截止时间、上下文恢复、流式内容放行时机以及审计脱敏等不宜从方法名推断的行为。错误标识与配置键保持稳定，不为中文化而修改协议。

重构拦截器时必须验证实际 `-javaagent` 启动，单元测试不能覆盖所有类加载和 Advice 可见性问题。保持受保护操作的前后检查顺序，尤其不能将检查移到工具副作用之后。

## 本地检查

从仓库根目录运行：

```bash
# 自动整理格式与无用导入；缺少花括号需要修改源码。
mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 spotless:apply

# 格式、规范、单元测试和集成测试。
bash scripts/verify.sh

# 完整发布验证、SBOM、隔离重建及发布包。
bash scripts/release.sh
```

格式与规范检查绑定 Maven `validate` 阶段，常规测试、验证和发布都会执行。提交前运行 `git diff --check`，避免引入空白错误。格式化配置是统一标准，IDE 配置由根目录 `.editorconfig` 提供。
