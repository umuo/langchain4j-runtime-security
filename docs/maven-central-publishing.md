# Maven Central 发布：从账号准备到 SDK 可引用

本仓库已准备 `io.github.umuo` 坐标和 MIT 许可证，Java 包名仍为 `io.agentsecurity.*`。本页讲第一次发布的操作步骤；**配置已准备不代表制品已发布**，只有 Portal 显示 PUBLISHED、并且 Maven 能从 Central 下载，才算完成。

首次建议使用 `0.1.0-alpha.1`。main 继续保留 `0.1.0-SNAPSHOT`；发布工作流只在自己的工作副本里统一版本，不自动修改 main、不自动创建 tag 或 GitHub Release。

## 1. 发布哪些东西

| groupId | artifactId | 用途 |
| --- | --- | --- |
| io.github.umuo | agent-security-parent | 子模块引用的父 POM，必须一起发布 |
| io.github.umuo | agent-security-core | 无 Spring 的 SDK 核心 |
| io.github.umuo | agent-security-policy | 工具策略、远程 Detector、版本编译 |
| io.github.umuo | agent-security-telemetry | 可选指标与日志导出 |
| io.github.umuo | agent-security-javaagent | 自动插桩 JAR，通过 JVM 启动加载 |

工作流用 `-pl` 和 `-am` 仅选择父 POM 与四个运行时模块。Central 插件还显式排除 demo／Boot fixture，防止它们进入发布 bundle。它们仍在前置完整验收中运行。

四个 JAR 制品需要 POM、主 JAR、sources JAR、Javadoc JAR、对应 PGP 签名和校验和；父 POM 不需要虚构源码／文档 JAR。[Central 制品要求](https://central.sonatype.org/publish/requirements/)

## 2. 你先完成的账号操作

### 2.1 注册账号和验证 namespace

用你控制的 GitHub 账号 `umuo` 登录 [Central Portal](https://central.sonatype.com/)。在账号的 namespace 页面确认 **io.github.umuo 已验证**。

GitHub 登录通常会自动建立对应 namespace；若没有，请按页面提示完成验证。选择了 Maven groupId 不等于已经取得发布权限。[namespace 官方步骤](https://central.sonatype.org/register/namespace/)

本项目选择 `io.github.umuo`，不能用其他账号未授权的 namespace 发布。旧 `io.agentsecurity` 坐标已经迁移；项目自己的 Maven 内部依赖和文档示例使用新坐标，Java import／SPI 文件名不变。

### 2.2 生成 Portal Token

进入 Portal 账号页，找到 **Generate User Token**，生成用于发布的 token，保存页面提供的 username 和 password。它们分别对应后文的 CENTRAL_USERNAME、CENTRAL_PASSWORD。

这里不是 GitHub Token，也不是账号网页登录密码。[官方 Token 步骤](https://central.sonatype.org/publish/generate-portal-token/)

### 2.3 准备签名密钥

在你自己的机器安装 GnuPG，生成受口令保护的发布密钥，查看完整 fingerprint：

```bash
gpg --full-generate-key
gpg --list-secret-keys --keyid-format LONG
```

使用你实际的密钥 fingerprint，将**公钥**发布到 Sonatype 支持的公钥服务器，供签名验证：

```bash
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_FULL_FINGERPRINT
```

不要发送私钥到公钥服务器。密钥创建、有效期及公钥分发见 [Sonatype PGP 指南](https://central.sonatype.org/publish/requirements/gpg/)。

将发布私钥导出到仓库外的私有文件，复制其完整 ASCII 内容到 GitHub Secret：

```bash
umask 077
mkdir -p "$HOME/.config/agent-security"
gpg --armor --export-secret-keys YOUR_FULL_FINGERPRINT \
  > "$HOME/.config/agent-security/publishing-key.asc"
```

GPG_PRIVATE_KEY 填入文件完整内容，包括 BEGIN／END 标记，**不是文件路径，也不需要再做 Base64 编码**。GPG_PASSPHRASE 是私钥口令，工作流要求非空。不要把这些值发到聊天、Git、工作流 YAML 或公开日志。

本项目使用 Maven GPG 插件的 **BC signer**，直接读取 MAVEN_GPG_KEY、MAVEN_GPG_PASSPHRASE；Actions runner 不需要导入密钥到 GnuPG keyring。只能用临时测试密钥证明配置工作，真实发布身份仍由你的密钥和 Portal 账号决定。[Maven GPG 参数](https://maven.apache.org/plugins/maven-gpg-plugin/sign-mojo.html)

## 3. 在 GitHub 配置 environment 和 Secrets

仓库：`umuo/langchain4j-runtime-security`。

1. Settings → Environments → New environment，名称 **maven-central**。
2. 按团队需求配置 required reviewers 和 main 分支限制；工作流声明 environment 本身不会替你建立审批规则。
3. 在该 environment 的 Secrets 中加入以下四项：

| Secret 名称 | 值 |
| --- | --- |
| CENTRAL_USERNAME | Portal Token 的 username |
| CENTRAL_PASSWORD | Portal Token 的 password |
| GPG_PRIVATE_KEY | 完整 ASCII 私钥文本 |
| GPG_PASSPHRASE | 私钥口令 |

仓库 Actions 需要启用并允许运行本项目工作流。环境审批与功能可用性受 GitHub 账号／仓库配置影响，应以实际 Settings 页面为准。不要给来自 fork 的 PR 提供发布 Secrets；本工作流只有手动触发入口。

## 4. 第一次上传操作

代码推送到 main 后，打开 Actions → **Upload SDK to Maven Central** → Run workflow：

- 分支选 **main**；其他分支不会执行发布任务。
- version 填 **0.1.0-alpha.1**，不带 `v`、不带 SNAPSHOT。
- 只有在 Portal 已确认 namespace 权限后，勾选 namespace_verified。

支持 `x.y.z` 和 `x.y.z-alpha.N`／`beta.N`／`rc.N`，拒绝非法版本与 shell 注入文本。版本准备器先验证全部 POM 一致，再更新整个 reactor，不改运行时 Java 代码。

工作流顺序：

```text
同一提交源码 + 指定版本
    → 完整发布验收、SBOM、隔离重建
    → sources / Javadoc 生成检查
    → maven-central environment 审批（若配置）
    → 同一提交与版本重新构建、签名
    → 上传 bundle，等待 Central VALIDATED
    → 你在 Portal 检查并点击 Publish
    → PUBLISHED 后验证用户能下载
```

本地生成检查和发布脚本用的是不同 runner，不声称跨 runner 已完成 JAR 哈希一致性验收。完整测试在 verify job 执行；upload job 根据同一提交重新构建，跳过重复测试。

未勾选 namespace_verified 时工作流会被跳过，不代表验证通过。勾选只是操作者声明，不会向 Sonatype 自动证明 namespace 所有权。

## 5. Portal 确认发布

打开 [Deployments](https://central.sonatype.com/publishing/deployments)，根据日志中的 deploymentId 找到上传记录，检查：

- groupId 是 io.github.umuo，版本与输入一致。
- 只有父 POM 和四个运行时模块。
- 必需制品和签名均通过校验。
- 没有使用测试密钥，源码提交与验收记录可追溯。

`autoPublish=false`，上传通过后仍需你点击 Publish。等状态变为 PUBLISHED，再进入下载验收。Central 同一版本发布后不能覆盖／删除，修复用新版本。[官方发布流程](https://central.sonatype.org/publish/publish-portal-maven/)

发布完成后记录版本、源码提交、deploymentId 和验收证据；若创建 Git tag，指向本次工作流的源码提交，而不是发布后另一个 main 提交。当前工作流不会自动替你创建 tag。

## 6. 发布成功后怎么引用

以下版本只有真正发布后才可从 Central 下载：

```xml
<dependency>
  <groupId>io.github.umuo</groupId>
  <artifactId>agent-security-core</artifactId>
  <version>0.1.0-alpha.1</version>
</dependency>
```

需要 ToolPolicy／远程检测器则增加 policy；需要 Prometheus／OTLP 则增加 telemetry。它们都会依赖 core，应用尽量统一版本。Central release 正常引用无需配置 GitHub Maven 仓库或 GitHub Token。

用一份临时空 Maven 缓存验证下载，避免本地已安装制品造成假成功：

```bash
mvn -B -ntp -Dmaven.repo.local=/tmp/agent-security-central-download \
  org.apache.maven.plugins:maven-dependency-plugin:3.8.1:get \
  -Dartifact=io.github.umuo:agent-security-core:0.1.0-alpha.1
```

构建一个只依赖新坐标的普通 Java 消费项目，再运行 [SDK 使用手册](sdk-user-guide.md) 的 SdkQuickStart 示例。不要在未发布时反复把 404 解释成账号错误；先核对状态、坐标及同步进度。

自动拦截还需要下载 Agent JAR 并放到部署目录，用 `-javaagent:...=policy.properties` 启动。Agent 制品的 Central 下载名按 Maven 坐标生成，通常是 `agent-security-javaagent-0.1.0-alpha.1.jar`；本地构建的固定文件名则是 `agent-security-javaagent.jar`。仅添加 core dependency 不会自动加载 Agent。

## 7. 本地制品准备与上传命令

先在独立发布工作副本执行，避免把 main 开发版本误改成发布版本：

```bash
python3 scripts/prepare_central_release.py --version 0.1.0-alpha.1
```

不需要密钥／Token的打包检查，**不会连接发布服务，也没有有效签名**：

```bash
mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 \
  -pl agent-security-core,agent-security-policy,agent-security-telemetry,agent-security-javaagent -am \
  -Pcentral-artifacts -DskipTests -Dgpg.skip=true package
```

准备好本地环境变量 CENTRAL_USERNAME、CENTRAL_PASSWORD、MAVEN_GPG_KEY、MAVEN_GPG_PASSPHRASE 后，完成测试再上传：

```bash
mvn -B -ntp -s .mvn/central-settings.xml -Dmaven.repo.local=.cache/m2 \
  -pl agent-security-core,agent-security-policy,agent-security-telemetry,agent-security-javaagent -am \
  -Pcentral-artifacts,central-upload clean deploy
```

本地上传命令会运行所选运行时模块测试，不自动执行 demo／Boot 全量矩阵；发布前仍执行 `bash scripts/release.sh`。不要在正式上传命令中加 `-Dgpg.skip=true`。`central-upload` 在 validate 阶段拒绝 SNAPSHOT；`central-artifacts` 本身可以用于开发版本的本地打包检查。

`.mvn/central-settings.xml` 只引用环境变量，不含凭据原文；原 `.mvn/settings.xml` 只管理依赖下载镜像，不能代替发布凭据配置。

## 8. 常见失败

| 现象 | 优先检查 |
| --- | --- |
| 工作流没有运行 | main 分支、namespace_verified、Actions 是否启用 |
| Missing publishing secret | environment 名称、四个 Secret 拼写与可用范围 |
| 401／403 | Portal Token 是否正确、是否过期／撤销、namespace 是否已授权 |
| SNAPSHOT 被拒绝 | 指定非 SNAPSHOT 版本，使用版本准备器 |
| GPG 签名失败 | ASCII 私钥是否完整、口令是否匹配、密钥是否可签名且有效 |
| 签名无法验证 | 公钥是否能从受支持服务器获取、是否使用了正确 fingerprint |
| 缺少 sources／Javadoc | 是否同时启用了 central-artifacts、是否选择全部运行时模块 |
| 版本已存在 | 改用新版本，不试图覆盖已发布版本 |
| GitHub workflow 成功但下载 404 | 可能仍是 VALIDATED，尚未手工 Publish；核对 PUBLISHED 状态及下载坐标 |

新 `groupId` 是 Maven 坐标迁移，旧本地 `io.agentsecurity` 的 SDK 依赖不会自动变成新坐标。应用更新 pom，统一 SDK／Agent／插件构建；Java import 保持不变。许可证声明覆盖本项目代码，依赖的第三方许可证仍保留自身要求。


## 9. 本轮验证证据与待完成事项

2026-10-03，Maven 坐标迁移后完整 `scripts/release.sh` 通过 **634 项测试，零失败、零错误、零跳过**；4 个运行时 JAR 隔离重建 SHA-256 一致，SBOM 与发布包包含新坐标和 LICENSE。SDK 的 Java 包名、运行时行为和既有测试数量未改变。

四个实际运行时模块的 sources／Javadoc 均生成且含源码／API HTML；7 项版本准备反例测试通过，连同既有验收器共 14 项 Python 测试通过。实际 POM 副本统一为 0.1.0-alpha.1 后 Central profile 的 validate 通过；原 SNAPSHOT 在 validate 阶段被拒绝。工作流 YAML 结构及手动触发、先验收后上传关系已本地解析核对，Wiki 严格构建通过。

从本仓库直接提取的 central-artifacts profile 在独立临时项目中，用一次性受口令保护的测试密钥签名；POM／JAR／sources／Javadoc 共 4 个签名经 OpenPGP 验证有效，测试私钥随后删除，未上传公钥或制品。

以上不表示账号 namespace 已验证、GitHub Secrets／environment 已配置、远端 Actions 已运行，或真实 Central bundle 已通过 Portal 校验。实际部署与冷缓存消费验收仍需按第 2～6 节操作；本轮没有向 Maven Central 上传或公开发布任何 SDK。
