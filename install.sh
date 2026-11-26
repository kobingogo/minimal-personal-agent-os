#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
PAOS_BIN="$REPO_DIR/bin/paos"

if ! command -v python3 >/dev/null 2>&1; then
  echo "错误：未检测到 python3（需 Python 3.9+ 标准库环境，无需安装任何 pip 包）。" >&2
  exit 1
fi

chmod +x "$PAOS_BIN" "$REPO_DIR"/hooks/*.py "$REPO_DIR"/hooks/*.sh

if [ "${1:-}" = "--dry-run" ]; then
  "$PAOS_BIN" matrix
  echo ""
  exec "$PAOS_BIN" harden --all --dry-run
fi

echo "==> [1/4] 非破坏性合并 Claude 沙盒钩子与 Codex Starlark 门禁 (自动备份已有配置)..."
"$PAOS_BIN" harden --all

echo ""
echo "==> [2/4] 运行词法级 PreToolUse 拦截器自检 (零外部依赖)..."
GATE="$HOME/.claude/hooks/pre_tool_gate.py"

assert_block() {
  local label="$1"
  local payload="$2"
  local rc=0
  printf '%s' "$payload" | "$GATE" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 2 ]; then
    echo "    [FAIL] 预期拦截却放行 (exit=$rc): $label" >&2
    exit 1
  fi
  echo "    [PASS] 已拦停 (exit 2): $label"
}

assert_allow() {
  local label="$1"
  local payload="$2"
  local rc=0
  printf '%s' "$payload" | "$GATE" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "    [FAIL] 预期放行却误杀 (exit=$rc): $label" >&2
    exit 1
  fi
  echo "    [PASS] 正常放行 (exit 0): $label"
}

assert_block "git push -f origin main"       '{"tool_name":"Bash","tool_input":{"command":"git push -f origin main"}}'
assert_block "gh repo create leak --public"  '{"tool_name":"Bash","tool_input":{"command":"gh repo create leak --public"}}'
assert_block "gh gist create -p ui.png"      '{"tool_name":"Bash","tool_input":{"command":"gh gist create -p ui.png"}}'
assert_block "echo \"\$(rm -fr ~)\""         '{"tool_name":"Bash","tool_input":{"command":"echo \"$(rm -fr ~)\""}}'
assert_block "篡改 ~/.claude/settings.json"  '{"tool_name":"Write","tool_input":{"file_path":"~/.claude/settings.json"}}'
assert_allow "rm -rf /tmp/cache"             '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/cache"}}'
assert_allow "commit 消息含 git push -f 文本" '{"tool_name":"Bash","tool_input":{"command":"git commit -m \"never run git push -f or rm -rf /\""}}'
assert_allow "env FOO=1 npm test"            '{"tool_name":"Bash","tool_input":{"command":"env FOO=1 npm test"}}'

echo ""
echo "==> [3/4] 运行本机 PAOS Doctor 真机体检..."
"$PAOS_BIN" doctor --workspace "$REPO_DIR" || true

echo ""
echo "==> [4/4] 扫描本机五大客户端 Cross-Harness 技能矩阵..."
"$PAOS_BIN" matrix

echo ""
echo "部署完成！建议将 paos 加入 PATH："
echo "  ln -sf \"$PAOS_BIN\" ~/.local/bin/paos"
echo "启动个人 OS：cd \"$REPO_DIR\" && claude （输入 /triage 开始今日分诊）"
