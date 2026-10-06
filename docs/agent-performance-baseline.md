# 打包 Agent 性能基准

本工具测量真实 `-javaagent` 插桩、文本提取、工具执行器、SPI 检测和审计 I/O。模型与工具是确定性本地模拟，不调用外部模型服务；不是 JMH、长期压力验收或生产 SLA。它补充 [遥测诊断基线](performance-baseline.md)，后者只测引擎与收集器。

## 运行

先构建 Agent 和演示依赖 JAR：

```bash
mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 \
  -pl agent-security-javaagent,demo -am -DskipTests package

# 快速冒烟，只验证计数、业务结果和报告结构，不用于性能结论。
python3 scripts/benchmark_agent.py --iterations 20 --forks 1 \
  --output target/benchmarks/agent-smoke.json

# 默认：每线程 2000 次，单线程，6 种模式 × 2 种场景 × 3 个独立 JVM。
python3 scripts/benchmark_agent.py

# 对比并发和较长文本，生成另一份报告；强制刷盘可能耗时较长。
python3 scripts/benchmark_agent.py --threads 1 4 --text-chars 10000 \
  --output target/benchmarks/agent-long-text.json

# 为流式两段之间增加 5ms 模拟等待，观察缓冲检查对首段交付的影响。
python3 scripts/benchmark_agent.py --scenarios stream --stream-delay-millis 5 \
  --output target/benchmarks/agent-stream-delay.json
```

脚本使用 JAVA_HOME 下的 java／javac，否则使用 PATH。参数限制：每线程 10～10000 次、1～16 个工作线程、累计最多 100000 次、1～10 个 fork、文本 2～100000 UTF-16 单元、流式片段等待 0～50ms。单个 fork 超时为 300 秒，超时或异常不会覆盖已有报告。过大的工作量和等待组合可能超时，应缩小参数，而不是忽略失败。

## 模式和场景

| 模式 | 实际配置 |
| --- | --- |
| no-agent | 不加载 Agent，作为同一模拟业务的基线 |
| no-policy | 加载 Agent，但不传策略路径，验证新构建跳过初始化 |
| minimal | 使用本地文本规则和 stderr 审计，无工具 JSON |
| file-buffered | 同样策略，文件审计，audit.force=false |
| file-forced | 同样策略，文件审计，每条记录强制刷盘 |
| plugin | 同样策略加 SPI Detector，验证共享插件实例及隔离检测调度 |

`mixed` 每次执行一次模型请求和一次 DefaultToolExecutor 工具调用，输入、输出均提取检查。`stream` 执行一次真实流式接口调用，输出两段，记录第一段交付和最终完成时间。所有模式使用相同文本、模拟结果和 classpath；stderr 都重定向到实际文件，避免控制台差异，重定向日志的成本仍包含在启用审计的模式中。

每个 fork 先进行 3 轮同场景预热，每轮最多 500 次／线程，然后正式测量。执行计划按固定 seed 打乱。固定堆为 256 MiB。模拟业务验证返回内容、调用次数和流式完成；插件模式还要求整个 JVM 只构造一个 Detector，即使 mixed 使用了不同请求类。阻断、结果丢失、漏调用、插件重复构造均使基准失败，不会被当作更高吞吐。

基准为控制变量设置 detector.timeout.millis=5000、audit.timeout.millis=5000，并使检测并发容量不小于工作线程数；**这些是基准参数，不是新的 SDK 默认值**。策略内容均为合成数据，不传入真实用户内容或凭据。

## 如何读报告

报告包含每个 fork 的 P50／P95／P99、吞吐、流式首段交付 P95、实际模型／工具调用数、插件构造和检查次数、测量前后堆使用量、GC 次数／耗时，以及审计文件和 stderr 字节数。汇总保留多 fork 中位数和 P95 范围。mixed 的 firstByteP95Nanos 为 0，表示不适用。

产物、Java 探针和脚本的 SHA-256、JDK、平台、CPU 数量、随机种子和参数一并保存，避免只用 Git SHA 表示未提交的构建。结果先写同目录临时文件，全部场景成功后原子替换报告。测试策略、审计和 stderr 文件放在临时目录，结束后删除；输出 JSON 是保留的本地文件。

注意区分测量范围：

- 延迟是模拟模型／工具／流式操作的端到端耗时，吞吐还包含调度、时钟及结果验证成本。
- 堆值是测量前后快照，不是分配速率、峰值或进程 RSS；GC 与延迟均受 JIT、磁盘、后台负载影响。
- 审计字节数包含预热和测量，轮转会保留有限备份，不是只统计测量窗口新增字节。
- 流式首段是模拟 SDK 回调的交付时间，不是实际模型服务的 token 首字时间。
- 不包含真实 LLM 网络、远程 Detector、RAG／Memory／MCP 数据源、TLS、异步工具或完整 Reactive Streams 压力。
- 短冒烟和少量迭代只能证明探针可运行。不要用单次数字宣布固定损耗百分比或把 no-policy 比 no-agent 更快解释成加速。

生产容量评估仍需真实 provider、业务数据量、并发、持续负载和故障注入。尤其要单独验证文件强制刷盘和流式缓冲的影响。CI 只运行短场景，不设置性能阈值。

## 本次诊断采样

2026-10-06，macOS arm64 / Azul JDK 21.0.4，用完整发布验收后的 JAR 执行以下命令。每线程仅 100 次、预热每轮 100 次，属于较短诊断样本，JIT 可能尚未充分稳定；不作为生产容量或默认参数下的长期基线。所有 36 个独立 JVM 均校验业务结果和计数通过。原始样本、产物及探针 SHA-256 见 [JSON 证据](evidence/agent-performance-baseline.json)。

```bash
python3 scripts/benchmark_agent.py --iterations 100 --forks 3 \
  --stream-delay-millis 2 --output target/benchmarks/agent-baseline.json
```

单线程，文本 1024 单元，两段流式输出间模拟等待 2ms；下表为三个 fork 的中位数，P95 单位为毫秒，吞吐为每秒操作数。mixed 的一次操作包含模型和工具各一次；不能与 stream 的一次模型调用直接比较吞吐。

| 模式 | mixed P95 | mixed 吞吐 | stream P95 | stream 首段 P95 |
| --- | ---: | ---: | ---: | ---: |
| no-agent | 0.047 | 27532 | 2.777 | 0.119 |
| no-policy | 0.059 | 26135 | 2.691 | 0.106 |
| minimal | 0.639 | 1748 | 3.297 | 3.290 |
| file-buffered | 0.300 | 3517 | 2.868 | 2.846 |
| file-forced | 46.276 | 25 | 25.987 | 25.959 |
| plugin | 0.848 | 1585 | 3.444 | 3.439 |

本样本中强制刷盘开销显著，具体数值依赖文件系统和磁盘；缓冲文件审计和 stderr 模式也有不同的编码与输出路径。流式启用安全检查后，第一段会等待完整输出检查再释放，所以其首段交付接近整次完成时间。无策略与无 Agent 的小幅差异包含运行波动，不应解释为固定损耗百分比或加速。

另外执行 `--iterations 20 --forks 1 --threads 4 --text-chars 10000`，六模式、两场景的 12 个 JVM 均通过实际调用与结果校验，插件仍只构造一次。该并发冒烟仅验证探针和共享插件的功能，样本量不支持性能结论；[原始证据](evidence/agent-concurrent-smoke.json) 保留参数及计数。
