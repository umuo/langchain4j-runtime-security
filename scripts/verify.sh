#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec mvn -B -ntp -s .mvn/settings.xml -Dmaven.repo.local=.cache/m2 clean verify "$@"
