# 故障恢复与大子树验证

本轮验证两个运行边界：导出后端持续失败后恢复，以及大量子任务同时失效。使用合成数据和本机协议端点，不访问外部模型，不等同于真实 Collector、TLS 或生产长时间断网验收。

## 可重复的恢复探针

先构建运行时模块，再运行探针。需要 JDK 17 或以上，并允许监听本机临时端口。

```bash
mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 -pl agent-security-telemetry -am package
python3 scripts/probe_exporter_recovery.py
```

默认 unavailable 模式先返回 10 秒 HTTP 503，再恢复 10 秒 HTTP 200；生产者约每 5ms 产生一个合成事件。收集器容量 128，导出批次 32，最多 3 次尝试，轮询 10ms，请求预算 1 秒。请求只发往探针自己启动的 `127.0.0.1` HTTP 端点。结束时停止生产，再以 10 秒预算调用 awaitDrained。

```bash
# CI 冒烟，验证编译、资源约束、故障后继续导出及计数。
python3 scripts/probe_exporter_recovery.py --outage-seconds 1 --recovery-seconds 2

# 自主选择较长运行；这里展示命令，不代表已执行。
python3 scripts/probe_exporter_recovery.py --outage-seconds 1800 --recovery-seconds 300 --output target/benchmarks/recovery-long.json
```

允许故障时长 1–3000 秒，恢复阶段 1–600 秒，两者合计不超过一小时；整个 Java 子进程也有超时。默认报告为 `target/benchmarks/exporter-recovery.json`。只有成功运行才原子替换报告，失败不会覆盖旧证据。

成功条件：出现导出故障、恢复后有确认接收、队列不超过 128、在途批次不超过 32、结束排空，并满足：

```text
生成数 = 确认接收数 + 导出器丢弃数 + 收集器队列丢弃数
```

报告保存版本、被测 JAR／探针源码 SHA-256、生成／确认／丢弃统计和首次观察到恢复的时长。`firstAcceptedAfterRecoveryNanos=-1` 表示生产期间没有观察到首次成功，仅在最终排空阶段确认；不伪造恢复时刻。堆使用和 JVM 线程数约每 100ms 抽样，包含同 JVM 的 HTTP 服务端及客户端，不是 SDK 独占资源，也不是真正峰值或 RSS。固定堆为 128 MiB，不足以证明长期无泄漏。

## 故障模式

`--failure-mode` 可选：

| 模式 | 故障阶段 | 额外核对 |
| --- | --- | --- |
| unavailable（默认） | HTTP 503 | 有故障计数，恢复后确认接收 |
| disconnect | 读取请求后直接关闭连接，不返回 HTTP 响应 | 导出器收到传输失败后继续恢复 |
| stall | 返回 HTTP 200 头和一个字节，延迟 2 秒后关闭未完成的响应体 | 必须实际触发请求超时 |

```bash
python3 scripts/probe_exporter_recovery.py --failure-mode disconnect --outage-seconds 5 --recovery-seconds 5 --output target/benchmarks/recovery-disconnect.json
python3 scripts/probe_exporter_recovery.py --failure-mode stall --outage-seconds 5 --recovery-seconds 5 --output target/benchmarks/recovery-stall.json
```

恢复阶段三种模式均返回有效 JSON 响应。服务端固定两个 daemon 工作线程和 16 个排队名额，退出时关闭服务端并中断处理线程。报告增加 failureMode 与 timeouts。CI 对三个模式分别执行 1 秒故障／2 秒恢复，报告分别保留，不相互覆盖。

连接直接断开不等同于网络黑洞；响应体停滞也不覆盖 DNS 或 TLS 握手失败。三种模式只扩展了本机协议故障范围。

## 大子树的安全顺序

`SubtreeStressTest` 创建一个根与 1023 个子任务，另有一个独立根。撤销目标根时，首条终止审计由测试闸门暂时阻塞；测试在审计尚未完成时验证所有后代已标记终止，独立根仍有效。放开审计后核对 1024 个节点各自唯一的终止记录，并确认活跃数只剩独立根。

这是资源有界的状态与审计顺序验证，不给出大子树撤销的生产延迟承诺。runtime 的锁和逐条审计仍会影响并发调用等待时间；此路径后续需要真实审计介质、不同子树规模与长时间负载测试。

## 排空与恢复测试

`RecoveryTest` 验证：

- 故障期间队列／在途批次有界，安全策略仍拒绝受保护调用。
- 503 恢复为 200 后，同一个导出器可以继续发送。
- 已取空的队列存在在途请求时，awaitDrained 不误报成功。
- 请求尚未完成时排空等待可超时，完成后可成功。
- 导出器关闭后不再接受工作，有剩余队列时排空返回 false。

## 本轮执行证据

315 项完整测试通过，包含 1024 节点子树测试及短时本机恢复测试；四个运行时 JAR 隔离重建一致。探针源码按 Java 17 编译通过，参数边界检查通过。此前默认探针受自动审核超时阻止，本轮已补跑。实际证据见下方运行报告；CI 命令在本机执行验证，不代表已有远端 CI 成功记录。

## 尚未验收

早期探针运行时本机没有 Docker 或 Collector，因此这些探针本身没有完成真实接入验收。后续已增加固定版本 Collector 的独立 HTTP／HTTPS／mTLS 八场景验收，见 [Collector 与 TLS 验收](collector-acceptance.md)。限流、网络分区、持久化恢复和数小时压力仍待完成；不能把两套测试的范围混为一谈。


## 已保存的本机运行报告

本轮对三种模式分别运行完整探针和 CI 短命令，共 6 次，均成功恢复、完成计数核对并排空。运行的是已经通过 315 项测试的同一组运行时 JAR；本轮后续改动只涉及探针、CI 和文档，未修改运行时代码。

| 模式／原始报告 | 故障+恢复阶段 | 生成 | 确认接收 | 导出器丢弃 | 队列丢弃 | 超时 |
| --- | --- | --- | --- | --- | --- | --- |
| [unavailable](evidence/recovery-unavailable.json) | 10+10 秒 | 3205 | 1742 | 674 | 789 | 0 |
| [disconnect](evidence/recovery-disconnect.json) | 5+5 秒 | 1604 | 940 | 322 | 342 | 0 |
| [stall](evidence/recovery-stall.json) | 5+5 秒 | 1589 | 821 | 2 | 766 | 5 |

三种完整探针的队列最高均为 128，在途批次最高均为 32。短命令报告分别为 [503](evidence/smoke-recovery-unavailable.json)、[连接断开](evidence/smoke-recovery-disconnect.json)、[响应体停滞](evidence/smoke-recovery-stall.json)。源码与产物哈希见原始 JSON。报告中的丢弃是设计允许的有界故障行为，不应解读成所有数据可靠送达。
