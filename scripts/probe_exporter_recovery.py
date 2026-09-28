#!/usr/bin/env python3
"""Local synthetic HTTP failure/recovery probe; not a real Collector acceptance test."""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--failure-mode", choices=["unavailable", "disconnect", "stall"], default="unavailable")
    parser.add_argument("--outage-seconds", type=int, default=10)
    parser.add_argument("--recovery-seconds", type=int, default=10)
    parser.add_argument("--output", type=Path, default=ROOT / "target/benchmarks/exporter-recovery.json")
    args = parser.parse_args()
    if not (1 <= args.outage_seconds <= 3000 and 1 <= args.recovery_seconds <= 600
            and args.outage_seconds + args.recovery_seconds <= 3600):
        parser.error("probe duration exceeds bounds")
    pom = ET.parse(ROOT / "pom.xml").getroot()
    version = pom.findtext("m:version", namespaces=NS)
    jackson = pom.findtext("m:properties/m:jackson-core.version", namespaces=NS)
    artifacts = [ROOT / name / "target" / f"{name}-{version}.jar"
                 for name in ("agent-security-core", "agent-security-telemetry")]
    artifacts.append(ROOT / f".cache/m2/com/fasterxml/jackson/core/jackson-core/{jackson}/jackson-core-{jackson}.jar")
    if not all(path.is_file() for path in artifacts):
        parser.error("Build first: mvn -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 -pl agent-security-telemetry -am package")
    home = os.environ.get("JAVA_HOME")
    java = str(Path(home) / "bin/java") if home else shutil.which("java")
    javac = str(Path(home) / "bin/javac") if home else shutil.which("javac")
    if not java or not javac:
        parser.error("Java and javac are required")
    source = ROOT / "benchmarks/ExporterRecoveryProbe.java"
    with tempfile.TemporaryDirectory(prefix="agent-security-recovery-") as classes:
        classpath = os.pathsep.join([classes, *(str(path) for path in artifacts)])
        subprocess.run([javac, "--release", "17", "-cp", classpath, "-d", classes, str(source)], check=True, timeout=60)
        result = subprocess.run([java, "-Xms128m", "-Xmx128m", "-cp", classpath, "ExporterRecoveryProbe",
                                 str(args.outage_seconds), str(args.recovery_seconds), args.failure_mode],
                                check=True, capture_output=True, text=True,
                                timeout=args.outage_seconds + args.recovery_seconds + 30)
    report = {"schemaVersion": 1, "kind": "local-synthetic-http-recovery",
              "createdAt": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
              "java": subprocess.check_output([java, "-version"], stderr=subprocess.STDOUT, text=True),
              "artifactSha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in artifacts},
              "sourceSha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "jvmArgs": ["-Xms128m", "-Xmx128m"], "result": json.loads(result.stdout)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=args.output.parent, delete=False) as output:
        json.dump(report, output, indent=2)
        output.write("\n")
        temporary = Path(output.name)
    temporary.replace(args.output)
    print(json.dumps(report["result"], indent=2))
    print(f"Saved {args.output}")


if __name__ == "__main__":
    main()
