#!/usr/bin/env python3
"""对真实打包 Agent 运行有界本机基准；不访问模型服务，不发布生产 SLA。"""
import argparse
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODES = ("no-agent", "no-policy", "minimal", "file-buffered", "file-forced", "plugin")


def validate_run(run, mode, scenario, threads, iterations):
    """阻断、丢结果或插件重复初始化不能作为有效性能样本。"""
    operations = threads * iterations
    if (run.get("mode") != mode or run.get("scenario") != scenario
            or run.get("threads") != threads or run.get("operations") != operations
            or run.get("modelCalls") != operations
            or run.get("toolCalls") != (operations if scenario == "mixed" else 0)
            or run.get("pluginConstructions") != (1 if mode == "plugin" else 0)
            or (mode == "plugin" and run.get("pluginChecks", 0) < 2 * operations)
            or not all(isinstance(run.get(key), (int, float)) and run[key] > 0
                       for key in ("elapsedNanos", "operationsPerSecond", "p50Nanos", "p95Nanos", "p99Nanos"))
            or (scenario == "stream" and run.get("firstByteP95Nanos", 0) <= 0)):
        raise ValueError("Invalid benchmark accounting or latency")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--threads", type=int, nargs="+", default=[1])
    parser.add_argument("--forks", type=int, default=3)
    parser.add_argument("--text-chars", type=int, default=1024)
    parser.add_argument("--scenarios", choices=("mixed", "stream"), nargs="+", default=["mixed", "stream"])
    parser.add_argument("--modes", choices=MODES, nargs="+", default=list(MODES))
    parser.add_argument("--stream-delay-millis", type=int, default=0)
    parser.add_argument("--seed", type=int, default=20261006)
    parser.add_argument("--output", type=Path, default=ROOT / "target/benchmarks/agent.json")
    args = parser.parse_args()
    if not (1 <= args.forks <= 10 and 10 <= args.iterations <= 10000
            and 2 <= args.text_chars <= 100000 and 0 <= args.stream_delay_millis <= 50
            and 1 <= len(args.threads) <= 4 and len(set(args.threads)) == len(args.threads)
            and all(1 <= count <= 16 and count * args.iterations <= 100000 for count in args.threads)
            and len(set(args.modes)) == len(args.modes)
            and len(set(args.scenarios)) == len(args.scenarios)):
        parser.error("benchmark limits exceeded")
    java_home = os.environ.get("JAVA_HOME")
    java = str(Path(java_home) / "bin/java") if java_home else shutil.which("java")
    javac = str(Path(java_home) / "bin/javac") if java_home else shutil.which("javac")
    if not java or not javac:
        parser.error("Java and javac are required")
    agent = ROOT / "agent-security-javaagent/target/agent-security-javaagent.jar"
    demo = ROOT / "demo/target/agent-security-demo.jar"
    if not agent.is_file() or not demo.is_file():
        parser.error("Build first: mvn -pl agent-security-javaagent,demo -am package")
    sources = [ROOT / "benchmarks/AgentBenchmark.java", ROOT / "benchmarks/AgentBenchmarkDetector.java"]
    plan = [(mode, scenario, threads, fork) for mode in args.modes for scenario in args.scenarios
            for threads in args.threads for fork in range(args.forks)]
    random.Random(args.seed).shuffle(plan)
    runs = []
    with tempfile.TemporaryDirectory(prefix="agent-security-full-benchmark-") as workspace:
        work = Path(workspace)
        classes = work / "classes"
        classes.mkdir()
        classpath = os.pathsep.join([str(classes), str(demo), str(agent)])
        subprocess.run([javac, "--release", "17", "-parameters", "-encoding", "UTF-8", "-cp", classpath,
                        "-d", str(classes)] + [str(source) for source in sources], check=True, timeout=60)
        for number, (mode, scenario, threads, fork) in enumerate(plan):
            folder = work / str(number)
            folder.mkdir()
            config = folder / "policy.properties"
            content = ("policy.version=benchmark\nmax.text.chars=\n"
                       "deny.text=BENCH_FORBIDDEN_MARKER\n"
                       f"detector.max.concurrent={max(threads, 4)}\n"
                       "detector.timeout.millis=5000\naudit.timeout.millis=5000\n"
                       f"stream.max.chars={args.text_chars + 100}\n")
            if mode.startswith("file-"):
                content += (f"audit.path={(folder / 'audit.jsonl').as_posix()}\naudit.backups=2\n"
                            f"audit.force={'true' if mode == 'file-forced' else 'false'}\n")
            config.write_text(content, encoding="utf-8")
            service = folder / "META-INF/services/io.agentsecurity.core.Detector"
            if mode == "plugin":
                service.parent.mkdir(parents=True)
                service.write_text("AgentBenchmarkDetector\n", encoding="utf-8")
            command = [java, "-Xms256m", "-Xmx256m"]
            if mode != "no-agent":
                command.append(f"-javaagent:{agent}" + ("" if mode == "no-policy" else f"={config}"))
            command += ["-cp", os.pathsep.join([str(folder), classpath]), "AgentBenchmark", mode, scenario,
                        str(threads), str(args.iterations), str(args.text_chars), str(args.stream_delay_millis)]
            started = datetime.now(timezone.utc)
            # stderr 审计写入真实文件；所有模式相同重定向，不把日志无限堆积在内存中。
            stderr = folder / "stderr.log"
            with stderr.open("wb") as log:
                result = subprocess.run(command, capture_output=False, stdout=subprocess.PIPE,
                                        stderr=log, text=True, timeout=300)
            if result.returncode != 0:
                detail = stderr.read_text(encoding="utf-8", errors="replace")[-4000:]
                raise RuntimeError(f"Benchmark failed: mode={mode}, scenario={scenario}, exit={result.returncode}\n{detail}")
            run = json.loads(result.stdout)
            validate_run(run, mode, scenario, threads, args.iterations)
            audit_files = [path for path in folder.glob("audit.jsonl*") if path.suffix != ".lock"]
            run.update({"fork": fork, "startedAt": started.isoformat(),
                        "stderrBytes": stderr.stat().st_size,
                        "auditBytes": sum(path.stat().st_size for path in audit_files),
                        "textChars": args.text_chars, "streamDelayMillis": args.stream_delay_millis})
            runs.append(run)
            print(f"{mode} {scenario} threads={threads} fork={fork}: "
                  f"p95={run['p95Nanos']}ns ops/s={run['operationsPerSecond']:.0f}", flush=True)
    summaries = []
    for mode in args.modes:
        for scenario in args.scenarios:
            for threads in args.threads:
                selected = [run for run in runs if (run["mode"], run["scenario"], run["threads"]) == (mode, scenario, threads)]
                summaries.append({"mode": mode, "scenario": scenario, "threads": threads,
                                  **{f"median{key[0].upper() + key[1:]}": statistics.median(run[key] for run in selected)
                                     for key in ("p50Nanos", "p95Nanos", "p99Nanos", "operationsPerSecond", "firstByteP95Nanos")},
                                  "minP95Nanos": min(run["p95Nanos"] for run in selected),
                                  "maxP95Nanos": max(run["p95Nanos"] for run in selected)})
    evidence = {"schemaVersion": 1, "kind": "packaged-agent-local-diagnostic-not-production-sla",
                "createdAt": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
                "cpuCount": os.cpu_count(), "java": subprocess.check_output([java, "-version"], stderr=subprocess.STDOUT, text=True),
                "artifactSha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (agent, demo)},
                "sourceSha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sources + [Path(__file__)]},
                "jvmArgs": ["-Xms256m", "-Xmx256m"], "seed": args.seed,
                "iterationsPerWorker": args.iterations, "forks": args.forks,
                "streamDelayMillis": args.stream_delay_millis, "textChars": args.text_chars,
                "runs": runs, "summaries": summaries}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=args.output.parent, delete=False) as output:
        json.dump(evidence, output, indent=2, ensure_ascii=False)
        output.write("\n")
        temporary = Path(output.name)
    temporary.replace(args.output)
    print(f"Saved {len(runs)} forks: {args.output}")


if __name__ == "__main__":
    main()
