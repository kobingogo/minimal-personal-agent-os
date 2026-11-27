"""Unified hook engines (`PreToolUse`, `Stop`, `SessionStart`) sharing PAOS audit & pgroup primitives."""

from __future__ import annotations

from datetime import date, timedelta
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import subprocess
import sys
from typing import List, Optional, Sequence, Tuple

from .audit import append_audit_event, paos_home, redact_truncate
from .scheduler import exec_with_pgroup_timeout
from .sync_bus import scan_unpromoted_tags

MAX_SESSION_START_CHARS = 3800

SHELL_KEYWORDS = {"{", "}", "then", "else", "elif", "do", "fi", "done", "!"}
SHELL_WRAPPERS = {"command", "nohup", "builtin", "time", "exec"}
SUDO_OPT_WITH_VAL = {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-U"}
SHELL_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "python", "python3", "node", "perl", "ruby"}
DOWNLOADERS = {"curl", "wget"}

GUARDRAIL_REL_PREFIXES = (
    ".claude",
    ".codex/rules",
    ".paos/config.json",
    ".paos/cron_jobs.json",
    ".paos/logs",
    ".paos/store",
    ".paos/brain/CORE_RULES.md",
    ".ssh",
    ".aws",
    ".config/gh",
    "Library/LaunchAgents",
)
REPO_GUARDRAIL_RE = re.compile(r"(^|/)(\.claude/(settings[^/]*\.json|hooks(/|$))|\.git/hooks(/|$))")
ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
TRAILING_REDIR_RE = re.compile(r"(?:\s*\d*(?:>>?|<<?|>&|&>|\|>)\s*[^\s;|&()]+)+\s*$")
REDIR_OP_TOKENS = {">", ">>", ">|", "&>", "1>", "1>>", "2>", "2>>", "<", "<<", "<<<", "<&", ">&"}
WRITE_REDIR_OPS = {">", ">>", ">|", "&>", "1>", "1>>", "2>", "2>>"}


def _block(reason: str, cwd: Optional[str] = None) -> "NoReturn":  # type: ignore[name-defined]
    append_audit_event(
        event_type="gate_block",
        status="blocked",
        summary=reason,
        harness="claude",
        cwd=cwd or os.getcwd(),
    )
    sys.stderr.write(f"[PAOS PreToolUse 拦截] {redact_truncate(reason, 400)}\n")
    sys.exit(2)


def _normalize_candidate_path(raw_path: str, cwd: Optional[str] = None) -> Tuple[str, str]:
    """Return `(home_rel_or_empty, normalized_abs_or_rel)` for tamper & rm checks."""
    home_str = str(paos_home()).rstrip("/")
    real_home_str = str(Path.home()).rstrip("/")
    s = raw_path.strip()
    if not s:
        return ("", "")

    for prefix in ("$HOME", "${HOME}", "~"):
        if s == prefix:
            s = home_str
            break
        if s.startswith(prefix + "/"):
            s = home_str + s[len(prefix) :]
            break

    if not s.startswith("/") and cwd:
        abs_norm = posixpath.normpath(posixpath.join(cwd, s))
    else:
        abs_norm = posixpath.normpath(s)
    # Collapse POSIX `//` double-leading-slash edge case (`posixpath.normpath("//") == "//"`)
    if abs_norm.startswith("//"):
        abs_norm = re.sub(r"^/+", "/", abs_norm)

    for h in dict.fromkeys((home_str, real_home_str)):
        if h and abs_norm == h:
            return (".", abs_norm)
        if h and abs_norm.startswith(h + "/"):
            return (abs_norm[len(h) + 1 :], abs_norm)
    return ("", abs_norm)


def matches_guardrail_path(raw_path: str, cwd: Optional[str] = None) -> bool:
    if not raw_path or raw_path.startswith("-"):
        return False
    home_rel, abs_norm = _normalize_candidate_path(raw_path, cwd=cwd)
    if home_rel:
        # Block touching `.codex` or `.paos` root directly (e.g. `rm -rf ~/.paos` or `mv ~/.codex ...`)
        if home_rel in (".claude", ".codex", ".paos", ".ssh", ".aws", ".config/gh", "Library/LaunchAgents"):
            return True
        for gp in GUARDRAIL_REL_PREFIXES:
            if home_rel == gp or home_rel.startswith(gp + "/"):
                # Allow reading/writing inside `~/.claude/skills*`? No: self-tampering of `.claude` hooks/settings is blocked;
                # protect `.claude/settings*` and `.claude/hooks*` and `.claude` root wipe!
                if gp == ".claude":
                    if home_rel == ".claude" or home_rel.startswith(".claude/hooks") or re.match(r"^\.claude/settings", home_rel):
                        return True
                    continue
                return True
    return bool(REPO_GUARDRAIL_RE.search(abs_norm))


SAFE_DOTENV_SUFFIXES = (".example", ".sample", ".template", ".dist", ".schema")
SYSTEM_TOP_DIRS = {
    "/Users",
    "/home",
    "/System",
    "/Library",
    "/Applications",
    "/etc",
    "/var",
    "/opt",
    "/usr",
    "/bin",
    "/sbin",
    "/private",
    "/Volumes",
}


def matches_sensitive_read_path(raw_path: str, cwd: Optional[str] = None) -> bool:
    """Defense-in-depth: block shell commands directly reading root credential or `.env` secret files."""
    if not raw_path or raw_path.startswith("-"):
        return False
    home_rel, abs_norm = _normalize_candidate_path(raw_path, cwd=cwd)
    base = posixpath.basename(abs_norm)
    if base == ".env" or (base.startswith(".env.") and not base.endswith(SAFE_DOTENV_SUFFIXES)):
        return True
    if not home_rel:
        return False
    for sp in (".paos/config.json", ".ssh", ".aws", ".config/gh"):
        if home_rel == sp or home_rel.startswith(sp + "/"):
            return True
    return False


def extract_command_substitutions(cmd: str) -> List[str]:
    """Extract balanced `$(...)`, `<(...)`, `>(...)`, and `` `...` `` outside single quotes."""
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
            if ch in ("$", "<", ">") and i + 1 < n and cmd[i + 1] == "(":
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
    """Split a shell command into `(operator_before, segment)` outside quotes and parens."""
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

    if in_single or in_double or paren_depth != 0:
        raise ValueError("Unbalanced quotes or parentheses in command")

    flush("")
    return segments


def unwrap_tokens(tokens: Sequence[str], depth: int, cwd: str) -> Tuple[str, List[str], bool]:
    """Strip leading env assignments, shell keywords, and wrapper binaries (`sudo`, `nice`, `env`, `timeout`)."""
    idx = 0
    total = len(tokens)

    while idx < total:
        while idx < total and (ENV_ASSIGN_RE.match(tokens[idx]) or tokens[idx] in SHELL_KEYWORDS):
            idx += 1
        if idx >= total:
            break

        base = os.path.basename(tokens[idx])
        if base in SHELL_WRAPPERS:
            idx += 1
            while idx < total and tokens[idx].startswith("-") and tokens[idx] != "--":
                idx += 1
            if idx < total and tokens[idx] == "--":
                idx += 1
            continue
        if base == "sudo":
            idx += 1
            while idx < total and tokens[idx].startswith("-"):
                opt = tokens[idx]
                if opt == "--":
                    idx += 1
                    break
                if opt in SUDO_OPT_WITH_VAL and idx + 1 < total:
                    idx += 2
                else:
                    idx += 1
            continue
        if base == "nice":
            idx += 1
            while idx < total and tokens[idx].startswith("-"):
                if tokens[idx] == "-n" and idx + 1 < total:
                    idx += 2
                else:
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
                idx += 1  # duration
            continue
        if base == "env":
            idx += 1
            saw_split_str = False
            while idx < total and (tokens[idx].startswith("-") or ENV_ASSIGN_RE.match(tokens[idx])):
                opt = tokens[idx]
                if opt == "--":
                    idx += 1
                    break
                if opt in ("-S", "--split-string") and idx + 1 < total:
                    saw_split_str = True
                    inspect_command(tokens[idx + 1], depth + 1, cwd=cwd)
                    idx += 2
                elif opt in ("-u", "-C") and idx + 1 < total:
                    idx += 2
                else:
                    idx += 1
            if idx >= total:
                return ("", [], False) if saw_split_str else ("env", [], True)
            continue
        if base == "xargs":
            idx += 1
            while idx < total and tokens[idx].startswith("-"):
                if tokens[idx] in ("-I", "-L", "-n", "-P", "-s", "-d", "-E") and idx + 1 < total:
                    idx += 2
                else:
                    idx += 1
            continue
        break

    if idx >= total:
        return ("", [], False)

    clean_tail = [t for t in tokens[idx + 1 :] if t != "}"]
    return (os.path.basename(tokens[idx]), clean_tail, False)


def _check_rm(args: Sequence[str], cwd: str) -> None:
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
                _block("检测到 `rm --no-preserve-root` 高危参数。", cwd=cwd)
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
        raw_s = t.strip()
        home_rel, abs_norm = _normalize_candidate_path(raw_s, cwd=None)
        is_root_or_glob = (
            abs_norm in ("/", "/*")
            or abs_norm in SYSTEM_TOP_DIRS
            or raw_s in ("/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "$HOME/*", "${HOME}/*")
        )
        is_parent_traversal = raw_s in ("..", "../", "../*") or raw_s.startswith("../..")
        is_home_root = home_rel in (".", "*")
        if is_root_or_glob or is_parent_traversal or is_home_root:
            if has_recursive or has_force:
                _block(f"禁止对根目录、系统顶层目录、家目录或父级目录执行递归/强制删除 (`rm ... {t}`)。", cwd=cwd)


def _check_git(args: Sequence[str], cwd: str) -> None:
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
                _block("禁止执行 `git push --force / -f / --force-with-lease`，请改用新分支 PR 或人工确认。", cwd=cwd)
            if a.startswith("-") and not a.startswith("--") and "f" in a[1:]:
                _block(f"禁止执行带强推参数的 `git push {a}`，请改用新分支 PR 或人工确认。", cwd=cwd)
            if a.startswith("+") and any(b in a for b in ("main", "master", "prod", "release")):
                _block(f"禁止强推覆盖受保护分支 (`git push {a}`)。", cwd=cwd)
    elif sub == "reset" and "--hard" in sub_args:
        _block("检测到 `git reset --hard` 可能丢弃未提交工作，请先 stash 或人工执行。", cwd=cwd)


def _check_gh(args: Sequence[str], cwd: str) -> None:
    idx = 0
    while idx < len(args):
        a = args[idx]
        if a in ("-R", "--repo", "--hostname") and idx + 1 < len(args):
            idx += 2
            continue
        if a.startswith("-"):
            idx += 1
            continue
        break
    rem = args[idx:]
    if len(rem) < 2:
        return
    noun, verb = rem[0], rem[1]
    rest = rem[2:]
    if noun == "repo" and verb == "create":
        if any(r == "--public" or r.startswith("--public=") for r in rest):
            _block("禁止自动创建公开 GitHub 仓库 (`gh repo create --public`，防范公开外泄)。", cwd=cwd)
    elif noun == "repo" and verb == "edit":
        for i, r in enumerate(rest):
            if r == "--visibility=public" or (r == "--visibility" and i + 1 < len(rest) and rest[i + 1] == "public"):
                _block("禁止自动将仓库改为公开可见 (`gh repo edit --visibility public`)。", cwd=cwd)
    elif noun == "repo" and verb == "delete":
        _block("禁止 Agent 自动删除远端 GitHub 仓库 (`gh repo delete`)。", cwd=cwd)
    elif noun == "gist" and verb == "create":
        has_pub = any(
            r == "--public"
            or r.startswith("--public=")
            or (r.startswith("-") and not r.startswith("--") and "p" in r[1:])
            for r in rest
        )
        if has_pub:
            _block("禁止自动创建公开 Gist (`gh gist create --public/-p`，防范数据外泄)。", cwd=cwd)


def _strip_leading_keywords_and_subshell(seg: str) -> Optional[str]:
    """If `seg` (after stripping leading `if/then/{` and trailing redirections) is `(...)`, return inner."""
    s = seg.strip()
    changed = True
    while changed:
        changed = False
        for kw in ("if", "then", "else", "elif", "do", "{", "!"):
            if s.startswith(kw) and (len(s) == len(kw) or s[len(kw)].isspace() or s[len(kw)] == "("):
                s = s[len(kw) :].strip()
                changed = True
        if s.endswith("}"):
            s = s[:-1].strip()
            changed = True

    s_no_redir = TRAILING_REDIR_RE.sub("", s).strip()
    if s_no_redir.startswith("(") and s_no_redir.endswith(")"):
        return s_no_redir[1:-1]
    return None


def _pad_redirections_outside_quotes(seg: str) -> str:
    """Insert spaces around shell redirection operators outside quotes so `shlex.split` separates them cleanly."""
    out: List[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(seg)
    while i < n:
        ch = seg[i]
        if ch == "\\" and not in_single and i + 1 < n:
            out.append(ch)
            out.append(seg[i + 1])
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
            i += 1
            continue
        if not in_single and not in_double:
            # Optional single-digit fd prefix (`1>`, `2>>`, `2>&1`)
            if ch in ("1", "2", "0") and i + 1 < n and seg[i + 1] in (">", "<"):
                prev_c = seg[i - 1] if i > 0 else " "
                if prev_c.isspace() or prev_c in (")", ";", "&", "|"):
                    op = ch + seg[i + 1]
                    step = 2
                    if i + 2 < n and seg[i + 2] in (">", "&", "|"):
                        op += seg[i + 2]
                        step = 3
                    out.append(f" {op} ")
                    i += step
                    continue
            if seg[i : i + 3] == "<<<":
                out.append(" <<< ")
                i += 3
                continue
            if seg[i : i + 2] in (">>", "<<", ">|", "&>", ">&", "<&"):
                out.append(f" {seg[i : i + 2]} ")
                i += 2
                continue
            if ch in (">", "<"):
                out.append(f" {ch} ")
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _split_redirection_tokens(tokens: Sequence[str]) -> Tuple[List[str], List[str], List[str]]:
    """Separate clean command tokens from write-redirection & read-redirection paths."""
    cmd_tokens: List[str] = []
    write_targets: List[str] = []
    read_targets: List[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok in REDIR_OP_TOKENS or re.match(r"^\d*(?:>&|<&)$", tok):
            target = tokens[i + 1] if i + 1 < n else ""
            if tok in WRITE_REDIR_OPS and target and not target.startswith("&") and target != "/dev/null":
                write_targets.append(target)
            elif tok in ("<", "0<") and target and not target.startswith("&"):
                read_targets.append(target)
            i += 2
            continue
        cmd_tokens.append(tok)
        i += 1
    return (cmd_tokens, write_targets, read_targets)


def inspect_command(cmd: str, depth: int = 0, cwd: Optional[str] = None) -> None:
    eff_cwd = cwd or os.getcwd()
    if depth > 5:
        _block("命令嵌套层级过深，拒绝放行。", cwd=eff_cwd)

    for inner in extract_command_substitutions(cmd):
        if inner.strip():
            inspect_command(inner, depth + 1, cwd=eff_cwd)

    try:
        segments = split_shell_segments(cmd)
    except ValueError as exc:
        _block(str(exc), cwd=eff_cwd)

    prev_binary = ""
    for op_before, seg in segments:
        padded_seg = _pad_redirections_outside_quotes(seg)
        try:
            raw_tokens = shlex.split(padded_seg.replace("(", " ( ").replace(")", " ) "), posix=True)
        except ValueError:
            raw_tokens = []
        _, seg_write_targets, seg_read_targets = _split_redirection_tokens(raw_tokens)
        for wt in seg_write_targets:
            if matches_guardrail_path(wt, cwd=eff_cwd):
                _block(f"禁止通过重定向写入安全配置、钩子或控制面目录 (`{wt}`)。", cwd=eff_cwd)
        for rt in seg_read_targets:
            if matches_sensitive_read_path(rt, cwd=eff_cwd):
                _block(f"禁止通过输入重定向读取高敏凭据文件 (`{rt}`)。", cwd=eff_cwd)

        subshell_inner = _strip_leading_keywords_and_subshell(seg)
        if subshell_inner is not None:
            inspect_command(subshell_inner, depth + 1, cwd=eff_cwd)
            prev_binary = ""
            continue

        try:
            split_toks = shlex.split(padded_seg.strip(), posix=True)
        except ValueError as exc:
            _block(f"Shell 语法解析失败 ({exc})，拒绝放行。", cwd=eff_cwd)

        tokens, _, _ = _split_redirection_tokens(split_toks)
        if not tokens:
            continue

        binary, args, env_dump = unwrap_tokens(tokens, depth=depth, cwd=eff_cwd)
        if not binary:
            prev_binary = ""
            continue

        if binary == "eval" and args:
            inspect_command(" ".join(args), depth + 1, cwd=eff_cwd)

        if op_before == "|" and prev_binary in DOWNLOADERS and binary in SHELL_INTERPRETERS:
            _block(f"禁止将远程下载内容直接通过管道交由解释器执行 (`{prev_binary} | {binary}`)。", cwd=eff_cwd)

        if binary in ("sh", "bash", "zsh", "dash", "ksh"):
            for i, a in enumerate(args):
                if (a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:])) and i + 1 < len(args):
                    inspect_command(args[i + 1], depth + 1, cwd=eff_cwd)

        if env_dump or binary == "printenv":
            _block("禁止打印全量环境变量 (`env` / `printenv`) 以防凭据进入上下文。", cwd=eff_cwd)
        if binary == "export" and ("-p" in args or not args):
            _block("禁止通过 `export` 导出打印全量环境变量。", cwd=eff_cwd)

        if binary == "rm":
            _check_rm(args, cwd=eff_cwd)
        elif binary == "git":
            _check_git(args, cwd=eff_cwd)
        elif binary == "gh":
            _check_gh(args, cwd=eff_cwd)
        elif binary.startswith("mkfs"):
            _block(f"禁止执行磁盘格式化命令 (`{binary}`)。", cwd=eff_cwd)
        elif binary == "dd" and any(a.startswith("of=/dev/") for a in args):
            _block("禁止使用 `dd` 直接写入块设备。", cwd=eff_cwd)

        if binary in ("rm", "mv", "cp", "tee", "chmod", "chown", "ln", "truncate") or (
            binary == "sed" and any(a.startswith("-i") for a in args)
        ):
            for a in args:
                if matches_guardrail_path(a, cwd=eff_cwd):
                    _block(f"禁止 Agent 修改、移动或删除安全控制面与凭证目录 (`{a}`)。", cwd=eff_cwd)

        if binary in ("cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "awk", "sed", "cp", "scp", "base64", "xxd"):
            for a in args:
                if matches_sensitive_read_path(a.lstrip("@"), cwd=eff_cwd):
                    _block(f"禁止直接读取根凭据或通知密钥文件 (`{a}`)。", cwd=eff_cwd)

        prev_binary = binary


def run_pre_tool_gate_main() -> int:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            _block("PreToolUse 输入为空，按 Fail-Closed 策略拦截。")

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            _block(f"PreToolUse JSON 解析失败 ({exc})，按 Fail-Closed 策略拦截。")

        if not isinstance(payload, dict):
            _block("PreToolUse 载荷格式异常。")

        cwd = str(payload.get("cwd") or os.getcwd())
        tool_name = str(payload.get("tool_name") or "")
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            _block("缺少 tool_input 字段。", cwd=cwd)

        if tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            file_path = str(
                tool_input.get("file_path")
                or tool_input.get("notebook_path")
                or tool_input.get("path")
                or ""
            )
            if matches_guardrail_path(file_path, cwd=cwd):
                _block(f"禁止修改安全控制面或根凭证文件: {file_path}", cwd=cwd)
            return 0

        cmd = tool_input.get("command")
        if cmd is None:
            return 0
        if not isinstance(cmd, str):
            _block("command 字段类型异常。", cwd=cwd)

        inspect_command(cmd, cwd=cwd)
        return 0
    except SystemExit:
        raise
    except Exception as exc:
        _block(f"安全钩子内部异常 ({exc})，默认拦截。")


# =============================================================================
# Stop Verification Breaker (`stop_verify`)
# =============================================================================


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


def run_stop_verify_main() -> int:
    verify_cmd = os.environ.get("PAOS_VERIFY_CMD", "").strip()
    if not verify_cmd:
        return 0

    max_retries = _env_int("PAOS_MAX_STOP_RETRIES", 2)
    timeout_sec = _env_int("PAOS_VERIFY_TIMEOUT", 45)

    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        payload = {}

    cwd = Path(payload.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    session_id = str(payload.get("session_id") or cwd)

    try:
        st = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(cwd),
            text=True,
            capture_output=True,
            timeout=5,
        )
        if st.returncode != 0 or not st.stdout.strip():
            return 0
    except Exception:
        return 0

    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]
    st_dir = paos_home() / ".paos" / "state"
    st_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    sf = st_dir / f"stop-retries-{digest}.count"

    retries = 0
    if sf.is_file():
        try:
            retries = int(sf.read_text(encoding="utf-8").strip() or "0")
        except ValueError:
            retries = 0

    # Always run verification FIRST so if the latest edit fixed the tests, we pass immediately!
    rc, stdout, stderr, timed_out = exec_with_pgroup_timeout(
        ["/bin/sh", "-c", verify_cmd], cwd=cwd, timeout_sec=timeout_sec
    )
    if not timed_out and rc == 0:
        sf.unlink(missing_ok=True)
        return 0

    # Verification failed: check if we've now exhausted `max_retries` automated retry turns!
    if retries >= max_retries:
        sf.unlink(missing_ok=True)
        append_audit_event(
            event_type="stuck_cap",
            status="tripped",
            summary=f"Stop verification `{verify_cmd}` failed {retries + 1} times; yielded to human",
            harness="claude",
            cwd=str(cwd),
        )
        sys.stderr.write(
            f"[PAOS Stuck-Cap 熔断] 自动验证已连续失败 {retries + 1} 次，停止自动重试并交回人工判断。\n"
        )
        return 0

    sf.write_text(str(retries + 1), encoding="utf-8")
    if timed_out:
        sys.stderr.write(f"[PAOS Stop 验证超时 ({retries + 1}/{max_retries})] `{verify_cmd}` 超过 {timeout_sec}s。\n")
        return 2

    tail = redact_truncate((stdout + "\n" + stderr).strip(), 1200)
    sys.stderr.write(f"[PAOS Stop 验证未通过 ({retries + 1}/{max_retries})] `{verify_cmd}` 失败：\n{tail}\n")
    return 2


# =============================================================================
# SessionStart Dynamic Memory Snapshot (`load_recent_memory`)
# =============================================================================


def _read_lines_safe(path: Path) -> List[str]:
    if not path.is_file():
        return []
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def build_memory_snapshot(
    root: Path,
    today: Optional[date] = None,
    home_dir: Optional[Path] = None,
) -> str:
    today = today or date.today()
    yesterday = today - timedelta(days=1)
    home = paos_home(home_dir)

    local_mem = root / "memory"
    shared_mem = home / ".paos" / "brain" / "memory"
    mem_dir = local_mem if local_mem.is_dir() else (shared_mem if shared_mem.is_dir() else None)
    if mem_dir is None:
        return ""

    out: List[str] = [f"=== Personal OS 开机状态 ({today.isoformat()}) ==="]

    today_lines = [l for l in _read_lines_safe(mem_dir / "TODAY.md") if l.strip()]
    if today_lines:
        out.append("--- 今日聚焦 (TODAY.md) ---")
        out.extend(today_lines[:25])

    inbox_lines = _read_lines_safe(mem_dir / "INBOX.md")
    inbox_items = sum(1 for l in inbox_lines if re.match(r"^\s*-\s+\S", l))
    out.append(f"--- 待分诊收件箱 (INBOX.md): {inbox_items} 条 ---")

    for d in (yesterday, today):
        d_str = d.isoformat()
        daily_lines = [l for l in _read_lines_safe(mem_dir / "daily" / f"{d_str}.md") if l.strip()]
        if daily_lines:
            out.append(f"--- 每日日志 ({d_str}) ---")
            out.extend(daily_lines[-20:])

    counts = scan_unpromoted_tags(mem_dir / "learnings.md")
    ready = [f"{t}({c}次)" for t, c in counts.most_common(5) if c >= 2]
    if ready:
        out.append(f"--- 进化提醒：检测到复发纠偏标签 {', '.join(ready)}，可运行 `paos promote` 审阅晋升 ---")

    joined = "\n".join(out)
    if len(joined) > MAX_SESSION_START_CHARS:
        notice = "\n...[开机快照超预算已显式截断，避免触发宿主 10k 静默预览；如需完整上下文请直接 Read ~/.paos/brain/memory/]"
        joined = joined[: MAX_SESSION_START_CHARS - len(notice)] + notice
    return joined + "\n"


def run_session_start_main() -> int:
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    snap = build_memory_snapshot(root)
    if snap:
        sys.stdout.write(snap)
    return 0
