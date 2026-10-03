#!/usr/bin/env python3
"""在发布工作副本中统一 reactor 版本；只改 POM，不上传、不操作 Git。"""
import argparse
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NS = {"m": "http://maven.apache.org/POM/4.0.0"}
GROUP = "io.github.umuo"
MODULES = ("agent-security-core", "agent-security-policy", "agent-security-telemetry",
           "agent-security-javaagent", "demo", "integration-spring-boot")
RELEASE_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:alpha|beta|rc)\.(?:0|[1-9][0-9]*))?"
)


def prepare(root: Path, version: str):
    if len(version) > 64 or RELEASE_VERSION.fullmatch(version) is None:
        raise ValueError("Use a release version such as 0.1.0-alpha.1 or 0.1.0; SNAPSHOT is not allowed")
    parent = ET.parse(root / "pom.xml").getroot()
    current = parent.findtext("m:version", namespaces=NS)
    if parent.findtext("m:groupId", namespaces=NS) != GROUP:
        raise ValueError("Unexpected release namespace")
    actual_modules = tuple(node.text for node in parent.findall("m:modules/m:module", NS))
    if actual_modules != MODULES:
        raise ValueError("Reactor module list changed; review the publishing scope")
    # 先验证整个 reactor，再写文件，避免后半部分 POM 不一致时留下部分版本修改。
    changes = []
    for module in ("", *MODULES):
        path = root / module / "pom.xml"
        node = ET.parse(path).getroot()
        scope = node if not module else node.find("m:parent", NS)
        if scope is None or scope.findtext("m:groupId", namespaces=NS) != GROUP:
            raise ValueError(f"Unexpected parent in {module or 'root'}")
        if scope.findtext("m:version", namespaces=NS) != current:
            raise ValueError(f"Inconsistent version in {module or 'root'}")
        if module and node.find("m:version", NS) is not None:
            raise ValueError(f"Explicit module version needs review: {module}")
        text = path.read_text(encoding="utf-8")
        marker = f"<version>{current}</version>"
        if text.count(marker) != 1:
            raise ValueError(f"Ambiguous version replacement in {module or 'root'}")
        changes.append((path, text.replace(marker, f"<version>{version}</version>", 1)))
    for path, text in changes:
        path.write_text(text, encoding="utf-8")
    return current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    old = prepare(ROOT, args.version)
    print(f"Prepared {GROUP} {old} -> {args.version}; no upload performed")


if __name__ == "__main__":
    main()
