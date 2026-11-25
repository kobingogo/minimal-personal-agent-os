#!/usr/bin/env bash
set -euo pipefail

# 跨平台原子目录锁（macOS 与 Linux 通用，避免依赖 flock）
LOCK="/tmp/personal-os-heartbeat.lock"
mkdir "$LOCK" 2>/dev/null || exit 0
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT

REPO_DIR="${PERSONAL_OS_DIR:-$HOME/personal-harness}"
cd "$REPO_DIR"

# 仅跑只读巡检，锁死单次预算与轮次上限
claude -p "阅读 HEARTBEAT.md，执行今日只读巡检并把最多 3 条要点追加到 memory/INBOX.md" \
  --max-budget-usd 1 --max-turns 12
