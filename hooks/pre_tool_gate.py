#!/usr/bin/env python3
"""Deterministic, shell-aware PreToolUse safety gate (Fail-Closed).

Parses Claude Code PreToolUse JSON from stdin, tokenizes shell command segments
respecting quotes while inspecting command substitutions, and blocks destructive
commands, force-pushes, public repo/gist exfiltration (PixelLeak pattern),
remote pipe-to-shell execution, full environment dumps, and guardrail tampering.

Exit codes:
  0 - Allowed
  2 - Blocked (stderr returned to the agent as deterministic feedback)
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from typing import List, Sequence, Tuple

SHELL_WRAPPERS = {"sudo", "command", "nohup", "builtin", "time"}
SHELL_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "node", "perl", "ruby"}
DOWNLOADERS = {"curl", "wget"}
DANGEROUS_RM_TARGETS = {"/", "/*", "~", "~/", "$HOME", "${HOME}", ".."}
GUARDRAIL_PATHS_RE = re.compile(
    r"(^|/|~/)(\.claude/(settings(\.local)?\.json|hooks(/|$)))"
)
SUBSHELL_CMD_RE = re.compile(r"\$\(([^()]+)\)|`([^`]+)`|<\(([^()]+)\)")
ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def block(reason: str) -> "NoReturn":  # type: ignore[name-defined]
    sys.stderr.write(f"[PAOS PreToolUse 拦截] {reason}\n")
    sys.exit(2)


def split_shell_segments(cmd: str) -> List[Tuple[str, str]]:
    """Split a shell command into (operator_before, segment) outside quotes.

    Returns a list of tuples where operator_before is '', '|', '&&', '||', ';', '&', or '\\n'.
    Raises ValueError on unbalanced quotes (treated fail-closed when ambiguous).
    """
    segments: List[Tuple[str, str]] = []
    buf: List[str] = []
    op_before = ""
    in_single = False
    in_double = False
    escaped = False
    paren_depth = 0
    i = 0
    n = len(cmd)

    while i < n:
        ch = cmd[i]
        if escaped:
            buf.append(ch)
            escaped = False
            i += 1
            continue

        if ch == "\\" and not in_single:
            buf.append(ch)
            escaped = True
            i += 1
            continue

        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue

        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue

        if not in_single and not in_double:
            if ch == "(":
                paren_depth += 1
                buf.append(ch)
                i += 1
                continue
            if ch == ")" and paren_depth > 0:
                paren_depth -= 1
                buf.append(ch)
                i += 1
                continue

            if paren_depth == 0:
                two = cmd[i : i + 2]
                if two in ("&&", "||"):
                    seg = "".join(buf).strip()
                    if seg:
                        segments.append((op_before, seg))
                    buf = []
                    op_before = two
                    i += 2
                    continue
                if ch in (";", "|", "&", "\n"):
                    seg = "".join(buf).strip()
                    if seg:
                        segments.append((op_before, seg))
                    buf = []
                    op_before = ch
                    i += 1
                    continue

        buf.append(ch)
        i += 1

    if in_single or in_double:
        raise ValueError("命令行引号未闭合，拒绝放行")

    tail = "".join(buf).strip()
    if tail:
        segments.append((op_before, tail))
    return segments


def unwrap_tokens(tokens: Sequence[str]) -> Tuple[str, List[str], bool]:
    """Strip env assignments and common wrappers (`sudo`, `env`, `timeout`).

    Returns (binary_basename, remaining_args, had_env_wrapper_only).
    """
    idx = 0
    total = len(tokens)
    while idx < total and ENV_ASSIGN_RE.match(tokens[idx]):
        idx += 1

    if idx >= total:
        return ("", [], False)

    while idx < total:
        base = os.path.basename(tokens[idx])
        if base in SHELL_WRAPPERS:
            idx += 1
            while idx < total and tokens[idx].startswith("-"):
                idx += 1
            continue
        if base == "timeout":
            idx += 1
            while idx < total and tokens[idx].startswith("-"):
                if tokens[idx] in ("-k", "-s") and idx + 1 < total:
                    idx += 2
                else:
                    idx += 1
            if idx < total:
                idx += 1  # skip duration
            continue
        if base == "env":
            idx += 1
            while idx < total and (tokens[idx].startswith("-") or ENV_ASSIGN_RE.match(tokens[idx])):
                if tokens[idx] in ("-u", "-C", "-S") and idx + 1 < total:
                    idx += 2
                else:
                    idx += 1
            if idx >= total:
                # `env` invoked without a subcommand -> dumps entire environment!
                return ("env", [], True)
            continue
        break

    if idx >= total:
        return ("", [], False)

    return (os.path.basename(tokens[idx]), list(tokens[idx + 1 :]), False)


def check_rm(args: Sequence[str]) -> None:
    has_recursive = False
    has_force = False
    targets: List[str] = []
    after_ddash = False

    for a in args:
        if after_ddash:
            targets.append(a)
            continue
        if a == "--":
            after_ddash = True
            continue
        if a.startswith("--"):
            if a == "--recursive":
                has_recursive = True
            elif a == "--force":
                has_force = True
            elif a == "--no-preserve-root":
                block("检测到 `rm --no-preserve-root` 高危参数。")
            continue
        if a.startswith("-") and len(a) > 1:
            flags = a[1:]
            if "r" in flags or "R" in flags:
                has_recursive = True
            if "f" in flags:
                has_force = True
            continue
        targets.append(a)

    for t in targets:
        norm = t.rstrip("/") if t not in ("/", "~/") else t
        if t in DANGEROUS_RM_TARGETS or norm in ("~", "$HOME", "${HOME}", ".."):
            if has_recursive or has_force:
                block(f"禁止对根目录或家目录执行递归/强制删除 (`rm ... {t}`)。")


def check_git(args: Sequence[str]) -> None:
    # Skip global git options like -C <dir>, -c <k=v>, --git-dir=...
    idx = 0
    while idx < len(args):
        a = args[idx]
        if a in ("-C", "-c", "--git-dir", "--work-tree") and idx + 1 < len(args):
            idx += 2
            continue
        if a.startswith("-"):
            idx += 1
            continue
        break

    if idx >= len(args):
        return
    sub = args[idx]
    sub_args = args[idx + 1 :]

    if sub == "push":
        for a in sub_args:
            if a in ("-f", "--force", "--mirror"):
                block("禁止执行 `git push --force / -f`，请改用新分支 PR 或人工确认。")
            if a.startswith("+") and any(b in a for b in ("main", "master", "prod", "release")):
                block(f"禁止强推覆盖受保护分支 (`git push {a}`)。")
    elif sub == "reset" and "--hard" in sub_args:
        # Warn/block destructive git reset --hard unless explicitly reviewed
        block("检测到 `git reset --hard` 可能丢弃未提交工作，请先 stash 或人工执行。")


def check_gh(args: Sequence[str]) -> None:
    if len(args) < 2:
        return
    noun, verb = args[0], args[1]
    rest = args[2:]
    if noun == "repo" and verb == "create":
        if "--public" in rest:
            block("禁止自动创建公开 GitHub 仓库 (`gh repo create --public`，防范 PixelLeak 外传)。")
    elif noun == "gist" and verb == "create":
        if "--public" in rest or "-p" in rest:
            block("禁止自动创建公开 Gist (`gh gist create --public/-p`，防范数据外泄)。")


def inspect_command(cmd: str, depth: int = 0) -> None:
    if depth > 4:
        block("命令嵌套层级过深，拒绝放行。")

    # Inspect embedded command substitutions `...`, $(...), <(...) even inside double quotes
    for m in SUBSHELL_CMD_RE.finditer(cmd):
        inner = m.group(1) or m.group(2) or m.group(3) or ""
        if inner.strip():
            inspect_command(inner, depth + 1)

    try:
        segments = split_shell_segments(cmd)
    except ValueError as exc:
        block(str(exc))

    prev_binary = ""
    for op_before, seg in segments:
        stripped = seg.strip()
        if stripped.startswith("(") and stripped.endswith(")"):
            inspect_command(stripped[1:-1], depth + 1)
            prev_binary = ""
            continue

        try:
            tokens = shlex.split(stripped, posix=True)
        except ValueError as exc:
            block(f"Shell 语法解析失败 ({exc})，拒绝放行。")

        if not tokens:
            continue

        binary, args, env_dump = unwrap_tokens(tokens)
        if not binary:
            prev_binary = ""
            continue

        # 1. Pipe-to-shell remote execution (`curl ... | bash`)
        if op_before == "|" and prev_binary in DOWNLOADERS and binary in SHELL_INTERPRETERS:
            block(f"禁止将远程下载内容直接通过管道交由解释器执行 (`{prev_binary} | {binary}`)。")

        # 2. Nested `bash -c "..."` / `sh -c "..."`
        if binary in ("sh", "bash", "zsh", "dash") and "-c" in args:
            c_idx = args.index("-c")
            if c_idx + 1 < len(args):
                inspect_command(args[c_idx + 1], depth + 1)

        # 3. Full environment credential dump
        if env_dump or binary == "printenv":
            block("禁止打印全量环境变量 (`env` / `printenv`) 以防凭据进入上下文。")
        if binary == "export" and ("-p" in args or not args):
            block("禁止通过 `export` 导出打印全量环境变量。")

        # 4. Destructive commands
        if binary == "rm":
            check_rm(args)
        elif binary == "git":
            check_git(args)
        elif binary == "gh":
            check_gh(args)
        elif binary.startswith("mkfs"):
            block(f"禁止执行磁盘格式化命令 (`{binary}`)。")
        elif binary == "dd" and any(a.startswith("of=/dev/") for a in args):
            block("禁止使用 `dd` 直接写入块设备。")

        # 5. Guardrail self-tampering protection
        if binary in ("rm", "mv", "cp", "tee", "chmod", "chown", "ln", "truncate") or (
            binary == "sed" and any(a.startswith("-i") for a in args)
        ):
            for a in args:
                if GUARDRAIL_PATHS_RE.search(a):
                    block(f"禁止 Agent 修改或覆盖自身安全配置与钩子 (`{a}`)。")

        # Also check output redirection `>` / `>>` targeting guardrail files
        if ">" in seg and GUARDRAIL_PATHS_RE.search(seg):
            block("禁止通过重定向写入 `.claude` 安全配置或钩子目录。")

        prev_binary = binary


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        block("PreToolUse 输入为空，按 Fail-Closed 策略拦截。")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        block(f"PreToolUse JSON 解析失败 ({exc})，按 Fail-Closed 策略拦截。")

    if not isinstance(payload, dict):
        block("PreToolUse 载荷格式异常。")

    tool_name = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        block("缺少 tool_input 字段。")

    # File write/edit protection if hooked onto Write|Edit
    if tool_name in ("Write", "Edit", "MultiEdit"):
        file_path = str(tool_input.get("file_path") or tool_input.get("path") or "")
        if GUARDRAIL_PATHS_RE.search(file_path):
            block(f"禁止修改安全控制面文件: {file_path}")
        return 0

    cmd = tool_input.get("command")
    if cmd is None:
        return 0
    if not isinstance(cmd, str):
        block("command 字段类型异常。")

    inspect_command(cmd)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # Fail-Closed on unexpected internal errors
        block(f"安全钩子内部异常 ({exc})，默认拦截。")
