#!/usr/bin/env python3
"""Run bounded local telemetry diagnostic forks; never publish a production SLA."""
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100000, help="operations per worker, max total 1000000")
    parser.add_argument("--threads", type=int, nargs="+", default=[1, 4])
    parser.add_argument("--forks", type=int, default=3)
    parser.add_argument("--capacity", type=int, default=1024)
    parser.add_argument("--seed", type=int, default=20260928)
    parser.add_argument("--output", type=Path, default=ROOT / "target/benchmarks/telemetry.json")
    args = parser.parse_args()
    if not (1 <= args.forks <= 10 and 100 <= args.iterations and 1 <= args.capacity <= 65536
            and args.threads and len(args.threads) <= 8 and len(set(args.threads)) == len(args.threads)
            and all(1 <= count <= 32 and count * args.iterations <= 1000000 for count in args.threads)):
        parser.error("benchmark limits exceeded")
    java_home = os.environ.get("JAVA_HOME")
    java = str(Path(java_home) / "bin/java") if java_home else shutil.which("java")
    javac = str(Path(java_home) / "bin/javac") if java_home else shutil.which("javac")
    if not java or not javac:
        parser.error("Java and javac are required")
    # 必须使用刚构建的 core JAR。报告保留实际产物哈希，不能只靠 Git SHA 表示未提交工作区。
    jars = sorted((ROOT / "agent-security-core/target").glob("agent-security-core-*.jar"))
    jars = [path for path in jars if not path.name.endswith(("-sources.jar", "-javadoc.jar"))]
    if len(jars) != 1:
        parser.error("Build core first: mvn -pl agent-security-core -am package")
    jar = jars[0]
    plan = [(mode, threads, fork) for mode in ("disabled", "draining", "stalled")
            for threads in args.threads for fork in range(args.forks)]
    random.Random(args.seed).shuffle(plan)
    runs = []
    with tempfile.TemporaryDirectory(prefix="agent-security-benchmark-") as classes:
        subprocess.run([javac, "--release", "17", "-cp", str(jar), "-d", classes,
                        str(ROOT / "benchmarks/TelemetryBenchmark.java")], check=True, timeout=60)
        for mode, threads, fork in plan:
            command = [java, "-Xms128m", "-Xmx128m", "-cp", os.pathsep.join([classes, str(jar)]),
                       "TelemetryBenchmark", mode, str(threads), str(args.iterations), str(args.capacity)]
            result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=150)
            run = json.loads(result.stdout)
            run["fork"] = fork
            runs.append(run)
            print(f"{mode} threads={threads} fork={fork}: p95={run['p95Nanos']}ns "
                  f"ops/s={run['operationsPerSecond']:.0f} dropped={run['dropped']}", flush=True)
    summaries = []
    for threads in args.threads:
        for mode in ("disabled", "draining", "stalled"):
            selected = [run for run in runs if run["mode"] == mode and run["threads"] == threads]
            summaries.append({"mode": mode, "threads": threads,
                              "medianP95Nanos": statistics.median(run["p95Nanos"] for run in selected),
                              "medianOperationsPerSecond": statistics.median(run["operationsPerSecond"] for run in selected),
                              "minP95Nanos": min(run["p95Nanos"] for run in selected),
                              "maxP95Nanos": max(run["p95Nanos"] for run in selected)})
    evidence = {"schemaVersion": 1, "kind": "local-diagnostic-not-production-acceptance",
                "createdAt": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
                "cpuCount": os.cpu_count(), "java": subprocess.check_output([java, "-version"], stderr=subprocess.STDOUT, text=True),
                "coreJarSha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
                "sourceSha256": hashlib.sha256((ROOT / "benchmarks/TelemetryBenchmark.java").read_bytes()).hexdigest(),
                "jvmArgs": ["-Xms128m", "-Xmx128m"], "iterationsPerWorker": args.iterations,
                "capacity": args.capacity, "forks": args.forks, "seed": args.seed,
                "warmupRounds": 3, "warmupIterationsPerWorker": min(args.iterations, 100000),
                "runs": runs, "summaries": summaries}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # 使用同目录临时文件原子替换，失败运行不会覆盖旧报告。
    with tempfile.NamedTemporaryFile(mode="w", dir=args.output.parent, delete=False) as output:
        json.dump(evidence, output, indent=2, ensure_ascii=False)
        output.write("\n")
        temporary = Path(output.name)
    temporary.replace(args.output)
    print(f"Saved {len(runs)} forks: {args.output}")


if __name__ == "__main__":
    main()
