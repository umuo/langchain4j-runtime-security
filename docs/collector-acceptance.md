# 真实 Collector 与 TLS 验收

本工具启动官方 OpenTelemetry Collector Contrib，将 SDK 的 OTLP/HTTP JSON 日志写入 Collector file exporter，再核对最终文件。它覆盖真实协议和证书接入，不替代远端存储、网络分区或长期压力验收。

## 一条命令运行矩阵

要求 JDK 17+、Python 3、OpenSSL（支持 `req -addext`），以及监听本机临时端口的权限。当前固定产物覆盖 macOS arm64 与 Linux x86_64。无需 Spring、Docker、外部模型或真实业务凭据。

在仓库根目录执行：

```bash
mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 -pl agent-security-telemetry -am package
python3 scripts/accept_collector.py --download-collector
```

若系统 Java 配置不正确，先将 `JAVA_HOME` 和 `PATH` 指向有效 JDK。脚本使用该 JDK 的 java、javac、keytool。

首次加 `--download-collector` 才允许下载；后续可省略，使用 `.cache/collector` 中的归档。固定 Collector Contrib **0.147.0**，不是自动追踪最新版。脚本内保存官方 GitHub release API 返回的两平台 SHA-256，下载及每次使用前均校验，执行程序每次从验证后的归档提取。校验不匹配会立即失败，不跳过或自动接受新摘要。版本升级需要审阅新摘要并重新运行验收。

工具仅向临时本机 Collector 发起请求；HTTP 对照场景只用于本机测试。证书私钥和测试信任库在独立临时目录创建，测试结束删除，不提交仓库、不进入 CI 产物。固定测试口令不用于生产配置。

## 场景与硬性通过条件

每个场景启动新的 Collector 和 Java 客户端进程，生成 105 条事件：100 次策略检查（50 次允许、50 次拒绝），加上真实父子 Agent 的创建、委托、一次工具检查、两个正常终止事件。采样为 1，队列容量 256，批次最多 100，单次请求预算 2 秒，仅尝试一次。结束时等待最多 30 秒排空。

| 场景 | SDK 确认数 | 导出丢弃数 | Collector 文件记录数 |
| --- | --- | --- | --- |
| HTTP 本机对照 | 105 | 0 | 105 |
| HTTPS，合法 CA 与 localhost SAN | 105 | 0 | 105 |
| 不信任服务端 CA | 0 | 105 | 0 |
| 主机名不匹配：用 IP 访问只有 DNS SAN 的证书 | 0 | 105 | 0 |
| 服务端证书已过期 | 0 | 105 | 0 |
| mTLS，双方证书合法 | 105 | 0 | 105 |
| mTLS，缺失客户端证书 | 0 | 105 | 0 |
| mTLS，客户端证书来自其他 CA | 0 | 105 | 0 |

所有场景要求队列丢弃为 0、最终在途为 0。正向场景导出失败数为 0；负向场景失败数必须大于 0。负向场景显示 `passed: true` 表示正确拒绝错误连接，不表示成功送达。

每次策略检查通过后才允许增加模拟副作用计数；50 次被拒绝的操作不能越过检测，允许的计数必须为 50。额外父子调用用于关联验证。这证明此测试中的 PolicyEngine 拒绝仍然有效，不声称测试覆盖所有 Java Agent 插桩路径。

验收先等 SDK 排空，再正常终止 Collector，使 file exporter 完成刷新，然后检查实际文件：

- 不只是总数相等：最终 eventId 集合与独立审计通道冻结的期望集合完全一致，正常链路不允许重复。
- 每条事件的 runId、phase、outcome 相同；父子事件额外核对 invocationId、parentInvocationId、depth、终止原因。
- service.name 正确，时间戳有效，耗时非负。
- 提示词、操作名称、租户和用户的测试敏感标记 `secret-` 不出现在落盘日志中。
- 错误证书场景实际文件中没有任何事件，不能只根据客户端异常判断成功。

## 如何阅读结果

每次运行在 `target/collector-acceptance/run-*/` 新建证据目录，不覆盖旧报告。

| 文件 | 用途 |
| --- | --- |
| `report.json` | 总通过状态、各场景计数、平台/JDK/Collector 版本、SDK JAR 和探针源码摘要 |
| `<场景>/collector.json` | 本次启动配置；证书临时路径在运行后失效，复跑应重新运行脚本 |
| `<场景>/collector.log` | Collector 启动、接收和关闭诊断 |
| `<场景>/client.json` | SDK 计数和从独立审计通道得到的期望事件属性 |
| `<场景>/logs.jsonl` | 实际 file exporter 输出；负向场景可能为空文件或没有文件 |

任何断言失败、编译失败、启动/关闭超时或非零退出都会导致脚本非零退出。证书生成之后的运行失败会保留 `passed: false` 和错误描述；环境/下载前置检查失败直接退出，不生成成功报告。排障首先查看当前运行目录，不使用旧报告作为本轮成功证据。

CI 在既有 JDK 17/21 矩阵构建后执行此脚本，并始终上传 `target/collector-acceptance/**`。本机通过与远端 CI 通过是两种证据；没有实际 CI 结果时不能声称跨平台矩阵通过。

## 明确没有覆盖的内容

- file exporter 正常退出后可读，不证明断电持久性，也不证明生产后端已经入库。
- 没有验证 Collector 重启、下游故障、认证 Header 的 401/403、证书轮换和吊销。
- 不覆盖真实 DNS 故障、TCP 黑洞、跨机网络分区、代理或负载均衡器。
- 当前矩阵检查正常完成的父子 Agent；撤销、过期在已有运行时测试中验证，未在此矩阵重复。
- 不将内存队列升级成可靠消息队列；进程崩溃仍可能丢数据。
- 没有运行数小时的真实业务压力，也未设定或宣称生产 P95/P99 SLA。

后续长期验收按 30 分钟预检、2 小时峰值压力、8～24 小时稳定性分阶段进行。需要预先固定业务 QPS、并发、负载分布、延迟预算和恢复预算，并保留时间序列、GC/JFR、线程/连接/文件句柄以及独立事件核对结果。现有短时恢复探针见 [故障恢复验证](recovery-validation.md)，不能替代以上验收。

## 配置依据

- [Collector file exporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.147.0/exporter/fileexporter)：OTLP JSON 文件输出与刷新。
- [Collector TLS 配置](https://github.com/open-telemetry/opentelemetry-collector/blob/v0.147.0/config/configtls/README.md)：服务端证书与 client_ca_file 双向验证。
- [固定版本官方发布](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.147.0)：运行产物来源。


## 本机执行证据

2026-09-28，macOS 15.3.2 arm64 / Zulu JDK 21.0.4 完整八场景通过。HTTP、HTTPS、mTLS 各确认并落盘 105 条；五个证书拒绝场景各确认 0 条、显式丢弃 105 条、落盘 0 条。每个场景均通过安全拒绝检查。汇总与逐文件校验和见 [原始报告](evidence/collector-acceptance.json)。完整原始配置、客户端清单和 Collector 文件保留在本次工作区 `target/collector-acceptance/run-lmxcl7pz/`；CI 执行时会独立生成并上传其证据目录。

验收器自身另有 7 个反例测试，防止只核对条数导致误判：缺失、重复、同数量事件替换、决策改变、敏感内容和负向场景错误接收必须失败。执行命令：

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
```
