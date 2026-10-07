#!/usr/bin/env bash
set -euo pipefail

# 在仓库根目录运行；仅构建教学 JAR，不修改 SDK 或业务源码。
cd "$(dirname "$0")/.."
task_java=java
task_javac=javac
task_jar=jar
if [[ -n "${JAVA_HOME:-}" ]]; then
  task_java="$JAVA_HOME/bin/java"
  task_javac="$JAVA_HOME/bin/javac"
  task_jar="$JAVA_HOME/bin/jar"
fi
task_bb_version=$(sed -n 's/.*<bytebuddy.version>\(.*\)<\/bytebuddy.version>.*/\1/p' pom.xml)
task_bb=".cache/m2/net/bytebuddy/byte-buddy/$task_bb_version/byte-buddy-$task_bb_version.jar"
if [[ ! -f "$task_bb" ]]; then
  echo "请先按入门文档的 Maven 命令构建 Agent，下载固定版本 Byte Buddy。" >&2
  exit 1
fi
task_output=target/bytebuddy-basics
mkdir -p "$task_output/classes"
"$task_javac" --release 17 -encoding UTF-8 -cp "$task_bb" \
  -d "$task_output/classes" examples/bytebuddy-basics/src/training/*.java
printf 'Manifest-Version: 1.0\nPremain-Class: training.PrintAgent\n\n' > "$task_output/print.mf"
printf 'Manifest-Version: 1.0\nPremain-Class: training.GuardAgent\nCan-Redefine-Classes: false\nCan-Retransform-Classes: false\n\n' > "$task_output/guard.mf"
"$task_jar" --create --file "$task_output/print-agent.jar" --manifest "$task_output/print.mf" \
  -C "$task_output/classes" training/PrintAgent.class
"$task_jar" --create --file "$task_output/guard-agent.jar" --manifest "$task_output/guard.mf" \
  -C "$task_output/classes" training/GuardAgent.class \
  -C "$task_output/classes" training/GuardAdvice.class
task_classpath="$task_output/classes:$task_bb"
case "${1:-allow}" in
  baseline) "$task_java" -cp "$task_classpath" training.Demo deleteAll ;;
  startup) "$task_java" "-javaagent:$task_output/print-agent.jar=hello" -cp "$task_classpath" training.Demo readCustomer ;;
  allow) "$task_java" "-javaagent:$task_output/guard-agent.jar" -cp "$task_classpath" training.Demo readCustomer ;;
  deny) "$task_java" "-javaagent:$task_output/guard-agent.jar" -cp "$task_classpath" training.Demo deleteAll ;;
  *) echo "用法：bash scripts/demo_bytebuddy.sh baseline|startup|allow|deny" >&2; exit 2 ;;
esac
