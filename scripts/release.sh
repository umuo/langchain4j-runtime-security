#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 -Prelease clean verify
python3 scripts/package_release.py
