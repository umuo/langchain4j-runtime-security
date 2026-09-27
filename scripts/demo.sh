#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec java "-javaagent:agent-security-javaagent/target/agent-security-javaagent.jar=${2:-config/demo.properties}" \
  -jar demo/target/agent-security-demo.jar "${1:-tool}"
