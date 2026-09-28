#!/usr/bin/env python3
"""固定版本真实 Collector / HTTPS / mTLS 验收；只监听和连接本机，不访问模型。"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.147.0"
# 来自官方 GitHub release API 的 asset digest，升级必须重新审阅并运行矩阵。
DIGESTS = {
    ("Darwin", "arm64"): ("darwin_arm64", "3b79e51fbd0a1eecba7c0f90f4022cf5b498ee7f19d34674f4eef8b0f1f24162"),
    ("Linux", "x86_64"): ("linux_amd64", "17cc9a8f2e44e80ceff0e0647aec18b28a6b1b17823040e362ddc4a9fd017ccc"),
}


def run(command, **kwargs):
    result = subprocess.run([str(value) for value in command], capture_output=True, text=True,
                            timeout=60, **kwargs)
    if result.returncode:
        raise RuntimeError(f"Command failed: {command[0]}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collector(download):
    target, digest = DIGESTS[(platform.system(), platform.machine())]
    cache = ROOT / ".cache/collector"
    cache.mkdir(parents=True, exist_ok=True)
    name = f"otelcol-contrib_{VERSION}_{target}.tar.gz"
    archive = cache / name
    if not archive.exists():
        if not download:
            raise RuntimeError("Collector missing; rerun with --download-collector (official pinned artifact)")
        url = f"https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v{VERSION}/{name}"
        with tempfile.NamedTemporaryFile(dir=cache) as temporary:
            with urllib.request.urlopen(url, timeout=120) as response:
                shutil.copyfileobj(response, temporary)
            temporary.flush()
            if sha(Path(temporary.name)) != digest:
                raise RuntimeError("Downloaded Collector checksum mismatch")
            shutil.copyfile(temporary.name, archive)
    if sha(archive) != digest:
        raise RuntimeError("Cached Collector checksum mismatch")
    binary = cache / f"otelcol-contrib-{VERSION}-{target}"
    # 只取一个普通文件，拒绝符号链接和路径穿越；每次从已校验归档重建。
    with tarfile.open(archive) as package:
        member = package.getmember("otelcol-contrib")
        if not member.isfile():
            raise RuntimeError("Collector archive member is not a regular file")
        with package.extractfile(member) as source, tempfile.NamedTemporaryFile(dir=cache, delete=False) as output:
            shutil.copyfileobj(source, output)
            temporary_binary = Path(output.name)
    temporary_binary.chmod(0o700)
    temporary_binary.replace(binary)
    return binary, digest


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def certificates(directory, keytool):
    for name in ("ca", "other"):
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-subj", f"/CN=acceptance-{name}", "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", directory / f"{name}.key",
             "-out", directory / f"{name}.pem"])
        run([keytool, "-importcert", "-noprompt", "-alias", name, "-file", directory / f"{name}.pem",
             "-keystore", directory / f"{name}.p12", "-storetype", "PKCS12", "-storepass", "acceptance-only"])
    for name, ca, days, usage in (("server", "ca", "2", "serverAuth"),
                                 ("expired", "ca", "-1", "serverAuth"),
                                 ("client", "ca", "2", "clientAuth"),
                                 ("wrong-client", "other", "2", "clientAuth")):
        extension = directory / f"{name}.ext"
        extension.write_text(f"subjectAltName=DNS:localhost\nextendedKeyUsage={usage}\nbasicConstraints=CA:FALSE\n")
        run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}",
             "-keyout", directory / f"{name}.key", "-out", directory / f"{name}.csr"])
        if name == "expired":
            # OpenSSL 新版拒绝负 days；用 CA 显式签发已过期但签名合法的证书。
            (directory / "index.txt").touch()
            (directory / "serial").write_text("1000\n")
            configuration = directory / "ca.cnf"
            configuration.write_text(
                f'[ca]\ndefault_ca=local\n[local]\ndatabase="{directory / "index.txt"}"\n'
                f'serial="{directory / "serial"}"\nnew_certs_dir="{directory}"\n'
                f'certificate="{directory / "ca.pem"}"\nprivate_key="{directory / "ca.key"}"\n'
                'default_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n')
            now = datetime.now(timezone.utc)
            run(["openssl", "ca", "-batch", "-notext", "-config", configuration,
                 "-in", directory / f"{name}.csr", "-extfile", extension,
                 "-startdate", (now - timedelta(days=2)).strftime("%Y%m%d%H%M%SZ"),
                 "-enddate", (now - timedelta(days=1)).strftime("%Y%m%d%H%M%SZ"),
                 "-out", directory / f"{name}.pem"])
        else:
            run(["openssl", "x509", "-req", "-in", directory / f"{name}.csr", "-CA", directory / f"{ca}.pem",
                 "-CAkey", directory / f"{ca}.key", "-CAcreateserial", "-days", days,
                 "-extfile", extension, "-out", directory / f"{name}.pem"])
        if usage == "clientAuth":
            run(["openssl", "pkcs12", "-export", "-inkey", directory / f"{name}.key", "-in",
                 directory / f"{name}.pem", "-out", directory / f"{name}.p12", "-passout", "pass:acceptance-only"])


def verify_sink(path, expected, success):
    content = path.read_text() if path.exists() else ""
    if "secret-" in content:
        raise RuntimeError("Sensitive fixture content leaked to Collector output")
    records = []
    for line in content.splitlines():
        for resource in json.loads(line).get("resourceLogs", []):
            attributes = {item["key"]: item["value"] for item in resource["resource"].get("attributes", [])}
            if attributes.get("service.name") != {"stringValue": "collector-acceptance"}:
                raise RuntimeError("Missing resource identity")
            for scope in resource.get("scopeLogs", []):
                records.extend(scope.get("logRecords", []))
    if len(records) != (len(expected) if success else 0):
        raise RuntimeError(f"Final sink count mismatch: {len(records)}")
    actual = {}
    for record in records:
        attributes = {item["key"]: next(iter(item["value"].values())) for item in record["attributes"]}
        identifier = attributes["security.event.id"]
        if identifier in actual:
            raise RuntimeError("Unexpected duplicate event in normal delivery")
        if int(attributes["security.duration.nanos"]) < 0 or int(record["timeUnixNano"]) <= 0:
            raise RuntimeError("Invalid timing attributes")
        actual[identifier] = attributes
    if success:
        if set(actual) != {item["security.event.id"] for item in expected}:
            raise RuntimeError("Final sink event ID set mismatch")
        for item in expected:
            if any(actual[item["security.event.id"]].get(key) != value for key, value in item.items()):
                raise RuntimeError("Final sink event attributes mismatch")
    return len(records)


def scenario(binary, certs, case, classpath, java, output):
    name, tls, mtls, server, trust, client, hostname, success = case
    directory = output / name
    directory.mkdir()
    number = port()
    protocol = {"endpoint": f"127.0.0.1:{number}"}
    if tls:
        protocol["tls"] = {"cert_file": str(certs / f"{server}.pem"), "key_file": str(certs / f"{server}.key")}
        if mtls:
            protocol["tls"]["client_ca_file"] = str(certs / "ca.pem")
    sink = directory / "logs.jsonl"
    config = {"receivers": {"otlp": {"protocols": {"http": protocol}}},
              "exporters": {"file": {"path": str(sink), "format": "json", "flush_interval": "100ms"}},
              "service": {"telemetry": {"metrics": {"level": "none"}},
                          "pipelines": {"logs": {"receivers": ["otlp"], "exporters": ["file"]}}}}
    config_path = directory / "collector.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    with (directory / "collector.log").open("w") as log:
        process = subprocess.Popen([str(binary), "--config", str(config_path)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"Collector exited: {directory / 'collector.log'}")
                try:
                    with socket.create_connection(("127.0.0.1", number), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Collector startup timeout")
                    time.sleep(0.1)
            response = run([java, "-Xms64m", "-Xmx128m", "-cp", classpath, "CollectorAcceptanceProbe",
                            f"{'https' if tls else 'http'}://{hostname}:{number}/v1/logs",
                            certs / f"{trust}.p12" if tls else "-",
                            certs / f"{client}.p12" if client else "-", str(success).lower()])
            result = json.loads(response)
            (directory / "client.json").write_text(json.dumps(result, indent=2) + "\n")
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise RuntimeError("Collector shutdown timeout")
        if process.returncode != 0:
            raise RuntimeError(f"Collector shutdown failed: {process.returncode}")
    result["sinkRecords"] = verify_sink(sink, result.pop("expected"), success)
    return {"name": name, "passed": True, **result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-collector", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "target/collector-acceptance")
    args = parser.parse_args()
    if (platform.system(), platform.machine()) not in DIGESTS:
        parser.error("Pinned binaries currently support macOS arm64 and Linux x86_64")
    home = os.environ.get("JAVA_HOME")
    java = str(Path(home) / "bin/java") if home else shutil.which("java")
    javac = str(Path(home) / "bin/javac") if home else shutil.which("javac")
    keytool = str(Path(home) / "bin/keytool") if home else shutil.which("keytool")
    if not all((java, javac, keytool, shutil.which("openssl"))):
        parser.error("JDK 17+ and OpenSSL required")
    pom = ET.parse(ROOT / "pom.xml").getroot()
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    version = pom.findtext("m:version", namespaces=ns)
    jackson = pom.findtext("m:properties/m:jackson-core.version", namespaces=ns)
    artifacts = [ROOT / name / "target" / f"{name}-{version}.jar"
                 for name in ("agent-security-core", "agent-security-telemetry")]
    artifacts.append(ROOT / f".cache/m2/com/fasterxml/jackson/core/jackson-core/{jackson}/jackson-core-{jackson}.jar")
    if not all(path.is_file() for path in artifacts):
        parser.error("Build core and telemetry modules first; see docs/collector-acceptance.md")
    binary, archive_digest = collector(args.download_collector)
    args.output.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="run-", dir=args.output.resolve()))
    report = {"schemaVersion": 1, "passed": False, "createdAt": datetime.now(timezone.utc).isoformat(),
              "collectorVersion": run([binary, "--version"]).strip(), "archiveSha256": archive_digest,
              "binarySha256": sha(binary), "platform": platform.platform(),
              "java": subprocess.check_output([java, "-version"], stderr=subprocess.STDOUT, text=True),
              "artifactSha256": {path.name: sha(path) for path in artifacts},
              "sourceSha256": {name: sha(ROOT / name) for name in
                               ("scripts/accept_collector.py", "benchmarks/CollectorAcceptanceProbe.java")},
              "cases": []}
    try:
        with tempfile.TemporaryDirectory(prefix="collector-certs-") as temporary:
            certs = Path(temporary)
            certificates(certs, keytool)
            source = ROOT / "benchmarks/CollectorAcceptanceProbe.java"
            classpath = os.pathsep.join([temporary, *(str(path) for path in artifacts)])
            run([javac, "--release", "17", "-cp", classpath, "-d", temporary, source])
            cases = [
                ("http", False, False, "server", "ca", None, "127.0.0.1", True),
                ("https", True, False, "server", "ca", None, "localhost", True),
                ("untrusted-server", True, False, "server", "other", None, "localhost", False),
                ("hostname-mismatch", True, False, "server", "ca", None, "127.0.0.1", False),
                ("expired-server", True, False, "expired", "ca", None, "localhost", False),
                ("mtls", True, True, "server", "ca", "client", "localhost", True),
                ("missing-client", True, True, "server", "ca", None, "localhost", False),
                ("untrusted-client", True, True, "server", "ca", "wrong-client", "localhost", False),
            ]
            for case in cases:
                print(f"Running {case[0]}", flush=True)
                report["cases"].append(scenario(binary, certs, case, classpath, java, output))
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        report["evidenceSha256"] = {str(path.relative_to(output)): sha(path)
                                    for path in sorted(output.rglob("*")) if path.is_file()}
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"Evidence: {output}", flush=True)


if __name__ == "__main__":
    main()
