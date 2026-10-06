# 遥测性能诊断基线

该工具用于比较同一机器上的配置变化、验证计数守恒及消费者停滞时的队列上限。它不是 JMH、生产压力验收或 SLA，也不设置延迟通过阈值。

## 运行

先用项目支持的 JDK 构建 core，再运行：

```bash
mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 -pl agent-security-core -am package
python3 scripts/benchmark_telemetry.py
```

脚本使用 JAVA_HOME 下的 java/javac，未设置时使用 PATH。默认 1／4 个工作线程、每线程 100000 次、每场景 3 个独立 JVM，共 18 个 JVM；固定 128 MiB 堆。每个 JVM 先执行三轮同场景预热，每轮最多每线程 100000 次，然后新建收集器开始测量。

```bash
# 快速检查工具能否运行，不用于性能结论。
python3 scripts/benchmark_telemetry.py --iterations 1000 --threads 1 --forks 1 --capacity 64

# 修改负载与容量，保留单独报告。
python3 scripts/benchmark_telemetry.py --iterations 200000 --threads 1 4 --forks 3 --capacity 4096 --output target/benchmarks/larger.json
```

每个 JVM 最多 32 个工作线程、1000000 个延迟样本；容量最多 65536，fork 最多 10。脚本设置子进程超时，任何执行异常、计数不守恒或队列越界均失败，不覆盖旧报告。运行顺序按固定 seed 打乱，便于重现；默认输出 `target/benchmarks/telemetry.json`。

## 测量范围

- disabled：关闭遥测的 PolicyEngine.check。
- draining：开启收集，一个额外线程持续拉取并丢弃关联记录；不执行序列化和网络发送。该消费者会消耗 CPU，不代表真实后端。
- stalled：开启收集但没有消费者，触发队列饱和及记录丢弃。

三个场景使用相同的预构造安全事件、空检测器列表和空审计回调。因此结果仅涉及检查引擎及收集器，不包含事件构造、Java Agent 插桩、真实检测器、文件审计、模型、工具、网络、AgentRuntime 生命周期或 OTLP 导出成本。

每次 check 前后用 nanoTime 记录延迟；吞吐包含测量循环、时钟及线程协调成本。每个 fork 输出 P50/P95/P99/max，汇总使用多个 fork 的中位数，并保留范围。短循环仍受 JIT、GC、操作系统调度和同机负载影响；不要将数值直接外推为生产能力或将负的延迟差解释为开启遥测更快。

堆数据是测量前后 MemoryMXBean 的已用堆快照，GC 数据是区间内累计次数／毫秒差。样本数组本身占用堆，不强制 GC；这不是每操作分配量、存活集、RSS 或峰值内存。持续运行的资源稳定性需要另做长时间压力和内存剖析。

## 本次本地证据

原始报告：[telemetry-baseline.json](evidence/telemetry-baseline.json)。报告包含操作系统、CPU 数、JDK、固定 JVM 参数、实际 core JAR 与基准源码 SHA-256，以及全部 fork 数据；以产物哈希识别被测代码，避免仅依赖 Git SHA 忽略工作区改动。

本次每个配置运行 3 个 fork，下表仅是本机短时诊断观察：

| 场景 | 工作线程 | P95 中位数（ns） | P95 范围（ns） | 吞吐中位数（次/秒） |
| --- | --- | --- | --- | --- |
| disabled | 1 | 458 | 458–459 | 2908435 |
| draining | 1 | 500 | 459–542 | 2127181 |
| stalled | 1 | 417 | 416–417 | 2504696 |
| disabled | 4 | 875 | 875–875 | 5695197 |
| draining | 4 | 875 | 875–1042 | 3431451 |
| stalled | 4 | 917 | 916–917 | 4723621 |

在 stalled 场景中，1 个线程的 100000 条记录保留 1024 条、丢弃 98976 条；4 个线程的 400000 条记录保留 1024 条、丢弃 398976 条。所有 18 个 fork 均完成计数核对。该证据证明本次负载下的边界行为，不证明长期无泄漏，也不证明所有监控场景的吞吐。

## 下一阶段验收

1. 引入长时间开放式负载和真实模型／工具路径，衡量排队及拒绝率，避免只测固定闭环。
2. 对大子树终止、审计延迟、后台过期扫描进行专项压测，记录 P95/P99 和业务尾延迟。
3. 连接真实 Collector，注入断网、限速和 TLS 故障，验证恢复、丢弃统计与连接资源。
4. 使用 JMH 或等效严谨基准隔离微小开销，配合 GC／分配与 CPU 剖析；生产门槛依据目标环境确定。

CI 只运行三个短场景检查编译、执行及计数约束，保存报告，不对性能数值设门槛。

需要测量真实插桩、文本提取、工具执行器和文件审计时，使用 [Agent 链路基准](agent-performance-baseline.md)。本页面的遥测基线不包含这些开销。
