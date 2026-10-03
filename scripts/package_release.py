#!/usr/bin/env python3
"""Package an already clean-verified reactor, checking reports and rebuilding runtime jars in isolation.

Use release.sh for the complete workflow. This script deliberately does not publish anything.
"""
import hashlib
import json
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
NS = {"m": "http://maven.apache.org/POM/4.0.0"}
VERSION = ET.parse(ROOT / "pom.xml").getroot().findtext("m:version", namespaces=NS)
MODULES = ["agent-security-core", "agent-security-policy", "agent-security-javaagent", "agent-security-telemetry", "demo", "integration-spring-boot"]
RUNTIME = MODULES[:4]
JARS = {module: ROOT / module / "target" / ("agent-security-javaagent.jar" if module.endswith("javaagent") else f"{module}-{VERSION}.jar") for module in RUNTIME}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_reports():
    counts = {}
    reports = []
    for module in MODULES:
        found = sorted((ROOT / module / "target").glob("*-reports/TEST-*.xml"))
        if not found:
            raise RuntimeError(f"Missing tests for {module}; run release.sh first")
        total = 0
        for path in found:
            suite = ET.parse(path).getroot()
            if any(int(suite.get(key, "0")) for key in ("failures", "errors", "skipped")):
                raise RuntimeError(f"Tests not clean: {path}")
            total += int(suite.get("tests", "0"))
        if not total:
            raise RuntimeError(f"No tests executed for {module}")
        counts[module] = total
        reports.extend(found)
    return counts, reports


def verify_jars():
    for jar in JARS.values():
        with ZipFile(jar) as archive:
            if archive.testzip() is not None:
                raise RuntimeError(f"Invalid JAR: {jar.name}")
    with ZipFile(JARS["agent-security-javaagent"]) as archive:
        names = archive.namelist()
        if any(name.startswith("dev/langchain4j/") and name.endswith(".class") for name in names):
            raise RuntimeError("Agent contains application LangChain4j classes")
        if "Premain-Class: io.agentsecurity.agent.SecurityAgent" not in archive.read("META-INF/MANIFEST.MF").decode():
            raise RuntimeError("Agent premain manifest missing")


def verify_reproducible():
    baseline = {module: digest(path) for module, path in JARS.items()}
    # No second test run: compare packaged runtime code, preserving the first build's reports and SBOMs.
    with tempfile.TemporaryDirectory(prefix="agent-security-rebuild-") as temporary:
        checkout = Path(temporary) / "source"
        shutil.copytree(ROOT, checkout, ignore=shutil.ignore_patterns(".git", ".cache", "target", ".idea", "__pycache__", "var", "*.log", "*.jsonl*"))
        log = ROOT / "target" / "reproducibility.log"
        command = ["mvn", "-B", "-ntp", "-s", str(ROOT / ".mvn/settings.xml"),
                   f"-Dmaven.repo.local={ROOT / '.cache/m2'}", "-pl", "agent-security-javaagent,agent-security-telemetry", "-am", "-DskipTests", "clean", "package"]
        with log.open("w") as output:
            subprocess.run(command, cwd=checkout, stdout=output, stderr=subprocess.STDOUT, check=True)
        for module, original in JARS.items():
            rebuilt = checkout / original.relative_to(ROOT)
            if digest(rebuilt) != baseline[module]:
                raise RuntimeError(f"Non-reproducible runtime JAR: {module}; see {log}")
    return baseline


def main():
    counts, reports = checked_reports()
    verify_jars()
    boms = {}
    for module in RUNTIME:
        path = ROOT / module / "target/bom.json"
        data = json.loads(path.read_text())
        if data.get("bomFormat") != "CycloneDX" or data.get("metadata", {}).get("component", {}).get("version") != VERSION:
            raise RuntimeError(f"Invalid SBOM for {module}")
        boms[module] = path
    hashes = verify_reproducible()
    destination = ROOT / "target/release" / f"agent-security-{VERSION}"
    if destination.exists():
        raise RuntimeError(f"Release output already exists: {destination}; run release.sh for a fresh build")
    destination.mkdir(parents=True)
    for module, jar in JARS.items():
        shutil.copy2(jar, destination / jar.name)
        shutil.copy2(boms[module], destination / f"{module}.sbom.json")
        shutil.copy2(ROOT / module / "pom.xml", destination / f"{module}.pom.xml")
    shutil.copy2(ROOT / "pom.xml", destination / "parent.pom.xml")
    for path in reports:
        relative = path.relative_to(ROOT)
        output = destination / "test-reports" / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, output)
    shutil.copytree(ROOT / "docs", destination / "docs")
    shutil.copytree(ROOT / "config", destination / "config")
    shutil.copy2(ROOT / "README.md", destination / "README.md")
    shutil.copy2(ROOT / "LICENSE", destination / "LICENSE")
    build = {"version": VERSION, "status": "production-acceptance-incomplete", "tests": counts,
             "runtimeJarSha256": hashes, "runtimeJarsReproduced": True,
             "reproducibilityScope": "same JDK/Maven, isolated source directory; runtime jars only",
             "java": subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT, text=True).strip(),
             "maven": subprocess.check_output(["mvn", "-version"], stderr=subprocess.STDOUT, text=True).strip()}
    (destination / "build-evidence.json").write_text(json.dumps(build, indent=2) + "\n")
    files = sorted(path for path in destination.rglob("*") if path.is_file())
    (destination / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.relative_to(destination).as_posix()}\n" for path in files))
    print(f"Packaged {sum(counts.values())} passing tests; {len(RUNTIME)} runtime JARs reproduced: {destination}")


if __name__ == "__main__":
    main()
