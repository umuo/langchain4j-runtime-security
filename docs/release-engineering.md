# 构建、交付证据与 CI

完整本地交付流程：

```bash
bash scripts/release.sh
```

需要 JDK、Maven、Python 3；首次运行访问 Maven Central。该流程只在本地产生交付文件，不发布 Maven 包、不创建 GitHub Release、不部署应用。

## 交付步骤

1. 执行 `-Prelease clean verify`，重新编译并运行单元及独立 JVM 集成测试。
2. 固定 CycloneDX Maven 插件 2.9.3 生成 schema 1.6 的 JSON SBOM。四个交付模块分别提供自己的运行时依赖清单，排除 test scope；聚合清单还包含演示及 Boot 测试应用，不能误当作 Agent 的运行时依赖集合。插件说明见 [官方文档](https://cyclonedx.github.io/cyclonedx-maven-plugin/)；SBOM 本身不是漏洞扫描结果。
3. 包装脚本检查每个模块都有执行过的测试报告，失败、错误、跳过均导致拒绝打包；检查 JAR 可读、Agent manifest 正确、没有打包 LangChain4j 应用类。
4. 在临时隔离源码目录重建 core、policy、Agent、telemetry，比较四个 JAR 的 SHA-256。第二遍仅重建运行时产物，不重复执行测试；第一遍报告和 SBOM 保留。不同则拒绝交付。
5. 输出到 `target/release/agent-security-0.1.0-SNAPSHOT/`：四个 JAR、模块 SBOM／POM、配置示例、文档、原始测试报告、build-evidence.json、SHA256SUMS。

源码通过 `project.build.outputTimestamp` 固定归档时间。同一 JDK／Maven 下不同源码目录的 JAR 一致性检查不代表跨 JDK、跨平台、跨 Maven 的全环境可重复构建。文档、SBOM、测试报告和构建环境记录作为证据保存；整个交付目录没有宣称逐字节可重复。

验证目录内容可运行：

```bash
cd target/release/agent-security-0.1.0-SNAPSHOT
shasum -a 256 -c SHA256SUMS
```

Linux 也可使用 `sha256sum -c SHA256SUMS`。校验和检查传输完整性，不证明发布者身份；目前尚无制品签名、可信时间戳或发布来源证明。仅限开发／验收使用，build-evidence 明确标记 `production-acceptance-incomplete`。

`scripts/package_release.py` 是流程的第二步，可用于刚完成 clean verify 后的本地诊断。它检查已有报告和产物，无法证明工作目录在测试之后没有修改；正式交付始终从 release.sh 开始。源码、依赖版本、配置和 JVM 应作为同一验收单元，SDK 与 Agent 不混用构建版本。

## 持续集成

`.github/workflows/verify.yml` 配置 Ubuntu 24.04、Temurin JDK 17／21 两个作业，运行同一 release.sh。Actions 固定到官方发布标签解析出的完整提交 SHA；checkout 不持久化凭据，工作流只有 contents:read 权限。无论成功或失败均尝试保留测试／交付证据，最长 14 天；作业上限 30 分钟，不自动发布。

CI 配置尚未在远端执行；本地当前仅验证 JDK 21.0.2，不能据配置文件宣称 JDK 17／Linux 已兼容。Dependabot 配置为 Maven 依赖和 Actions 的周更新，但更新建议不能替代兼容性回归或漏洞修复评估。

## 未完成的发布要求

2026-09-27 06:28（Asia/Shanghai）通过 OSV querybatch 核对当前两个第三方运行时依赖：Byte Buddy 1.17.8 与 Jackson Core 2.22.1，响应均无已知漏洞条目。原始请求坐标、响应和时间保存在 [查询证据](evidence/runtime-dependencies-2026-09-27.json)。这是该数据库在查询时的已知记录，不是无漏洞证明；未覆盖构建插件、CI Actions、JDK 或业务应用的 LangChain4j／provider 依赖，也尚未接入自动发布阻断。

仍需远端 CI 实际通过、依赖漏洞扫描及处置记录、许可证审查、发布签名与来源证明、跨环境构建比对、性能／压力数据和真实业务灰度。不要把 SBOM、固定 SHA 或一次本地重建当成已经完成供应链审计。当前版本保持 SNAPSHOT，完整验收状态见 [清单](production-readiness.md)。
