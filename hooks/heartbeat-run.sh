#!/usr/bin/env bash
set -euo pipefail

# 优先委托给 PAOS 原生定时调度内核（自带 ~/.paos/locks 进程级死锁自愈、多引擎选择、脱敏审计与通知总线）
REAL_SCRIPT="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$REAL_SCRIPT")" && pwd)"
PAOS_BIN="${SCRIPT_DIR}/../bin/paos"
if [[ ! -x "$PAOS_BIN" ]]; then
  PAOS_BIN="${HOME}/.local/bin/paos"
fi

if [[ -x "$PAOS_BIN" ]]; then
  exec "$PAOS_BIN" cron run-now heartbeat
fi

# 兜底：若脚本被单独拷贝且本机未挂载 paos CLI，使用 ~/.paos/locks 私有锁 + 只读工具约束执行
LOCK_ROOT="${HOME}/.paos/locks"
mkdir -p -m 700 "$LOCK_ROOT"
LOCK="${LOCK_ROOT}/heartbeat-standalone.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  if [[ -f "$LOCK/pid" ]] && ! kill -0 "$(cat "$LOCK/pid" 2>/dev/null || echo 0)" 2>/dev/null; then
    rm -rf "$LOCK"
    mkdir "$LOCK" 2>/dev/null || exit 0
  else
    exit 0
  fi
fi
echo "$$" > "$LOCK/pid"
trap 'rm -rf "$LOCK" 2>/dev/null || true' EXIT

REPO_DIR="${PERSONAL_OS_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
cd "$REPO_DIR"

claude -p "只读阅读 HEARTBEAT.md，生成最多 3 条简短巡检提醒（每行 - 开头）" \
  --tools "Read,Grep,Glob" --max-budget-usd 1 --max-turns 10
