#!/usr/bin/env python3
"""Deterministic, shell-aware PreToolUse safety gate (Fail-Closed).

Parses Claude Code PreToolUse JSON from stdin, tokenizes shell command segments
respecting quotes while inspecting nested command substitutions, and blocks destructive
commands, force-pushes, public repo/gist exfiltration (PixelLeak pattern),
remote pipe-to-shell execution, full environment dumps, and guardrail tampering.

Exit codes:
  0 - Allowed
  2 - Blocked (stderr returned to the agent as deterministic feedback)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import sys
from typing import List, Sequence, Tuple

SHELL_WRAPPERS = {"sudo", "command", "nohup", "builtin", "time", "exec", "nice", "{", "}", "then", "else", "elif", "do"}
SHELL_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "node", "perl", "ruby"}
DOWNLOADERS = {"curl", "wget"}
DANGEROUS_RM_TARGETS = {"/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "$HOME/*", "${HOME}/*", ".."}
GUARDRAIL_PATHS_RE = re.compile(
    r"(^|/|~/)(\.claude/(settings(\.local)?\.json|hooks(/|$))|\.codex/rules(/|$)|\.paos/logs(/|$))"
)
ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _scrub_inline_secrets(text: str) -> str:
    out = re.sub(r"\bsk-[a-zA-Z0-9_-]{12,}", "***REDACTED***", text)
    out = re.sub(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{16,}", "***REDACTED***", out)
    out = re.sub(r"\bgithub_pat_[a-zA-Z0-9_]{16,}", "***REDACTED***", out)
    out = re.sub(r"\bAIza[a-zA-Z0-9_-]{16,}", "***REDACTED***", out)
    out = re.sub(r"\bxox[baprs]-[a-zA-Z0-9-]{12,}", "***REDACTED***", out)
    out = re.sub(r"\b(?:bot)?\d{8,12}:[A-Za-z0-9_-]{30,}", "***REDACTED***", out)
    out = re.sub(r"((?:postgres|postgresql|mysql|mongodb|redis|https?)://[^/\s:@]+:)[^/\s@]+(@)", r"\1***REDACTED***\2", out)
    out = re.sub(r"(\bBearer\s+)[A-Za-z0-9._~+/=-]{16,}", r"\1***REDACTED***", out, flags=re.I)
    out = re.sub(
        r"(\b(?:[A-Za-z0-9_]+_)?(?:PASSWORD|PASSWD|API_KEY|APIKEY|AUTH_TOKEN|ACCESS_TOKEN|SECRET_KEY|PRIVATE_KEY|BOT_TOKEN|WEBHOOK_URL|CLIENT_SECRET|ACCESS_KEY|SECRET|TOKEN)\b\s*[:=]\s*['\"]?)[^\s'\"&,;}\]]{4,}",
        r"\1***REDACTED***",
        out,
        flags=re.I,
    )
    return out


def _record_gate_block_audit(reason: str) -> None:
    """Best-effort redacted audit log write to `~/.paos/logs/audit.jsonl` (zero external deps)."""
    try:
        from datetime import datetime

        home = Path(os.environ.get("PAOS_HOME_DIR") or Path.home())
        log_file = home / ".paos" / "logs" / "audit.jsonl"
        log_file.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        safe_reason = _scrub_inline_secrets(reason)[:400]
        rec = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "event": "gate_block",
            "status": "blocked",
            "harness": "claude",
            "cwd": os.getcwd(),
            "summary": safe_reason,
        }
        with log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        os.chmod(log_file, 0o600)
    except Exception:
        pass


def block(reason: str) -> "NoReturn":  # type: ignore[name-defined]
    _record_gate_block_audit(reason)
    sys.stderr.write(f"[PAOS PreToolUse 拦截] {reason}\n")
    sys.exit(2)


def _normalize_for_guardrail_check(raw_path: str) -> str:
    home_str = str(Path.home())
    s = raw_path.strip()
    if s.startswith("$HOME/"):
        s = "~/" + s[6:]
    elif s.startswith("${HOME}/"):
        s = "~/" + s[8:]
    elif home_str and s.startswith(home_str + "/"):
        s = "~/" + s[len(home_str) + 1 :]
    if s.startswith("~/"):
        rel = posixpath.normpath("/" + s[2:]).lstrip("/")
        return "~/" + rel
    return posixpath.normpath(s)


def _matches_guardrail_path(raw_path: str) -> bool:
    if GUARDRAIL_PATHS_RE.search(raw_path):
        return True
    norm = _normalize_for_guardrail_check(raw_path)
    return bool(GUARDRAIL_PATHS_RE.search(norm))


def extract_command_substitutions(cmd: str) -> List[str]:
    """Extract balanced `$(...)`, `<(...)`, and `` `...` `` outside single quotes."""
    results: List[str] = []
    in_single = False
    i = 0
    n = len(cmd)
    while i < n:
        ch = cmd[i]
        if ch == "\\" and not in_single and i + 1 < n:
            i += 2
            continue
        if ch == "'":
            in_single = not in_single
            i += 1
            continue
        if not in_single:
            if ch in ("$", "<") and i + 1 < n and cmd[i + 1] == "(":
                depth = 1
                j = i + 2
                sub_single = False
                while j < n and depth > 0:
                    c2 = cmd[j]
                    if c2 == "\\" and not sub_single and j + 1 < n:
                        j += 2
                        continue
                    if c2 == "'":
                        sub_single = not sub_single
                    elif not sub_single:
                        if c2 == "(":
                            depth += 1
                        elif c2 == ")":
                            depth -= 1
                    j += 1
                if depth == 0:
                    results.append(cmd[i + 2 : j - 1])
                    i = j
                    continue
            elif ch == "`":
                j = i + 1
                while j < n:
                    if cmd[j] == "\\" and j + 1 < n:
                        j += 2
                        continue
                    if cmd[j] == "`":
                        break
                    j += 1
                if j < n and cmd[j] == "`":
                    results.append(cmd[i + 1 : j])
                    i = j + 1
                    continue
        i += 1
    return results


def split_shell_segments(cmd: str) -> List[Tuple[str, str]]:
    """Split a shell command into (operator_before, segment) outside quotes."""
    segments: List[Tuple[str, str]] = []
    buf: List[str] = []
    op_before = ""
    in_single = False
    in_double = False
    paren_depth = 0
    i = 0
    n = len(cmd)

    def flush(next_op: str) -> None:
        nonlocal op_before
        seg = "".join(buf).strip()
        buf.clear()
        if seg:
            segments.append((op_before, seg))
            op_before = next_op
        elif not segments:
            op_before = next_op

    while i < n:
        ch = cmd[i]
        if ch == "\\" and not in_single and i + 1 < n:
            buf.append(ch)
            buf.append(cmd[i + 1])
            i += 2
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
                    flush(two)
                    i += 2
                    continue
                if ch in ("|", ";", "\n"):
                    flush(ch)
                    i += 1
                    continue
                if ch == "&":
                    prev_ch = cmd[i - 1] if i > 0 else ""
                    next_ch = cmd[i + 1] if i + 1 < n else ""
                    if prev_ch != ">" and next_ch != ">":
                        flush("&")
                        i += 1
                        continue

        buf.append(ch)
        i += 1

    if in_single or in_double:
        raise ValueError("Unbalanced quotes in command")

    flush("")
    return segments


def unwrap_tokens(tokens: Sequence[str]) -> Tuple[str, List[str], bool]:
    """Strip leading env assignments and wrapper binaries (`sudo`, `env`, `timeout`, `{`, `then`, etc.)."""
    idx = 0
    total = len(tokens)

    while idx < total and ENV_ASSIGN_RE.match(tokens[idx]):
        idx += 1

    while idx < total:
        tok = tokens[idx]
        if tok in ("{", "}", "then", "else", "elif", "do", "fi", "done"):
            idx += 1
            continue
        base = os.path.basename(tok)
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
                idx += 1
            continue
        if base == "env":
            idx += 1
            while idx < total and (tokens[idx].startswith("-") or ENV_ASSIGN_RE.match(tokens[idx])):
                if tokens[idx] in ("-u", "-C", "-S") and idx + 1 < total:
                    idx += 2
                else:
                    idx += 1
            if idx >= total:
                return ("env", [], True)
            continue
        break

    if idx >= total:
        return ("", [], False)

    clean_tail = [t for t in tokens[idx + 1 :] if t != "}"]
    return (os.path.basename(tokens[idx]), clean_tail, False)


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

    home_real = str(Path.home()).rstrip("/")
    for t in targets:
        norm = t.rstrip("/") if t not in ("/", "~/") else t
        is_home_real = bool(home_real and (norm == home_real or t == f"{home_real}/*"))
        if t in DANGEROUS_RM_TARGETS or norm in ("~", "$HOME", "${HOME}", "..") or is_home_real:
            if has_recursive or has_force:
                block(f"禁止对根目录或家目录执行递归/强制删除 (`rm ... {t}`)。")


def check_git(args: Sequence[str]) -> None:
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
            if a in ("-f", "--force", "--mirror") or a.startswith("--force-with-lease"):
                block("禁止执行 `git push --force / -f / --force-with-lease`，请改用新分支 PR 或人工确认。")
            if a.startswith("-") and not a.startswith("--") and "f" in a[1:]:
                block(f"禁止执行带强推参数的 `git push {a}`，请改用新分支 PR 或人工确认。")
            if a.startswith("+") and any(b in a for b in ("main", "master", "prod", "release")):
                block(f"禁止强推覆盖受保护分支 (`git push {a}`)。")
    elif sub == "reset" and "--hard" in sub_args:
        block("检测到 `git reset --hard` 可能丢弃未提交工作，请先 stash 或人工执行。")


def check_gh(args: Sequence[str]) -> None:
    if len(args) < 2:
        return
    noun, verb = args[0], args[1]
    rest = args[2:]
    if noun == "repo" and verb == "create":
        if "--public" in rest:
            block("禁止自动创建公开 GitHub 仓库 (`gh repo create --public`，防范 PixelLeak 外传)。")
    elif noun == "repo" and verb == "delete":
        block("禁止 Agent 自动删除远端 GitHub 仓库 (`gh repo delete`)。")
    elif noun == "gist" and verb == "create":
        if "--public" in rest or "-p" in rest:
            block("禁止自动创建公开 Gist (`gh gist create --public/-p`，防范数据外泄)。")


def inspect_command(cmd: str, depth: int = 0) -> None:
    if depth > 4:
        block("命令嵌套层级过深，拒绝放行。")

    for inner in extract_command_substitutions(cmd):
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

        # 0. `eval` recursive inspection
        if binary == "eval" and args:
            inspect_command(" ".join(args), depth + 1)

        # 1. Pipe-to-shell remote execution (`curl ... | bash`)
        if op_before == "|" and prev_binary in DOWNLOADERS and binary in SHELL_INTERPRETERS:
            block(f"禁止将远程下载内容直接通过管道交由解释器执行 (`{prev_binary} | {binary}`)。")

        # 2. Nested `bash -c / -lc / -ec "..."`
        if binary in ("sh", "bash", "zsh", "dash", "ksh"):
            for i, a in enumerate(args):
                if (a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:])) and i + 1 < len(args):
                    inspect_command(args[i + 1], depth + 1)

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

        # 5. Guardrail self-tampering protection (normalized path traversal safe)
        if binary in ("rm", "mv", "cp", "tee", "chmod", "chown", "ln", "truncate") or (
            binary == "sed" and any(a.startswith("-i") for a in args)
        ):
            for a in args:
                if _matches_guardrail_path(a):
                    block(f"禁止 Agent 修改或覆盖安全控制面与审计日志 (`{a}`)。")

        if ">" in seg:
            for tok in tokens:
                cleaned_tok = tok.lstrip("0123456789>&")
                if cleaned_tok and _matches_guardrail_path(cleaned_tok):
                    block("禁止通过重定向写入安全配置、钩子或审计日志目录。")

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

    if tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        file_path = str(
            tool_input.get("file_path")
            or tool_input.get("notebook_path")
            or tool_input.get("path")
            or ""
        )
        if _matches_guardrail_path(file_path):
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
    except Exception as exc:
        block(f"安全钩子内部异常 ({exc})，默认拦截。")
