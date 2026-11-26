"""Idempotent security hardening across Claude Code & Codex CLI, deep JSON merge & rollback."""

from __future__ import annotations

import copy
from datetime import datetime
import difflib
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

HOOK_FILES = (
    "pre_tool_gate.py",
    "load_recent_memory.py",
    "stop_verify.py",
    "block-destructive.sh",
    "load-recent-memory.sh",
    "heartbeat-run.sh",
)

REQUIRED_DENY_READ = ["~/.ssh/**", "~/.aws/**", "~/.config/gh/**", "**/.env*"]
REQUIRED_DENY_WRITE = ["~/.claude/**", "~/.codex/rules/**", "~/.paos/logs/**"]
DEFAULT_ALLOWED_DOMAINS = [
    "github.com",
    "*.githubusercontent.com",
    "registry.npmjs.org",
    "api.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
]
REQUIRED_PERMISSIONS_DENY = [
    "Read(.env)",
    "Read(.env.*)",
    "Read(**/.env)",
    "Read(**/.env.*)",
    "Read(~/.ssh/**)",
    "Read(~/.aws/**)",
    "Read(~/.config/gh/**)",
    "Read(~/.paos/config.json)",
    "Write(~/.claude/**)",
    "Edit(~/.claude/**)",
    "Write(~/.codex/rules/**)",
    "Edit(~/.codex/rules/**)",
    "Write(~/.paos/logs/**)",
    "Edit(~/.paos/logs/**)",
]
GATE_COMMAND = "~/.claude/hooks/pre_tool_gate.py"


def _dedup_extend(existing: List[Any], additions: List[Any]) -> List[Any]:
    out = list(existing)
    for item in additions:
        if item not in out:
            out.append(item)
    return out


def merge_claude_settings(current: Dict[str, Any]) -> Dict[str, Any]:
    """Non-destructively merge PAOS sandbox, permissions.deny & PreToolUse hook."""
    merged = copy.deepcopy(current) if isinstance(current, dict) else {}

    sb = merged.setdefault("sandbox", {})
    if not isinstance(sb, dict):
        sb = {}
        merged["sandbox"] = sb
    sb["enabled"] = True
    sb["failIfUnavailable"] = True
    sb["allowUnsandboxedCommands"] = False

    fs = sb.setdefault("filesystem", {})
    if not isinstance(fs, dict):
        fs = {}
        sb["filesystem"] = fs
    fs["denyRead"] = _dedup_extend(list(fs.get("denyRead") or []), REQUIRED_DENY_READ)
    fs["denyWrite"] = _dedup_extend(list(fs.get("denyWrite") or []), REQUIRED_DENY_WRITE)

    net = sb.setdefault("network", {})
    if not isinstance(net, dict):
        net = {}
        sb["network"] = net
    if not net.get("allowedDomains"):
        net["allowedDomains"] = list(DEFAULT_ALLOWED_DOMAINS)

    perms = merged.setdefault("permissions", {})
    if not isinstance(perms, dict):
        perms = {}
        merged["permissions"] = perms
    perms["deny"] = _dedup_extend(list(perms.get("deny") or []), REQUIRED_PERMISSIONS_DENY)

    hooks = merged.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        merged["hooks"] = hooks
    pre_list = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre_list, list):
        pre_list = []
        hooks["PreToolUse"] = pre_list

    already_wired = False
    for entry in pre_list:
        if not isinstance(entry, dict):
            continue
        inner = entry.get("hooks")
        if isinstance(inner, list):
            for h in inner:
                if isinstance(h, dict) and any(
                    k in str(h.get("command") or "")
                    for k in ("pre_tool_gate.py", "block-destructive.sh")
                ):
                    already_wired = True
                    break

    if not already_wired:
        pre_list.append(
            {
                "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit",
                "hooks": [
                    {
                        "type": "command",
                        "command": GATE_COMMAND,
                    }
                ],
            }
        )

    return merged


def verify_codex_rules_file(rules_path: Path) -> Tuple[bool, List[str]]:
    """Validate Starlark rules via `codex execpolicy check` if `codex` CLI is installed."""
    codex_bin = shutil.which("codex")
    if not codex_bin:
        return (True, ["codex CLI 未安装，已跳过编译器静态校验（语法符合 Starlark prefix_rule 规范）"])

    probes = [
        (["rm", "-rf", "/"], "forbidden"),
        (["git", "push", "-f", "origin", "main"], "forbidden"),
        (["git", "reset", "--hard", "HEAD~1"], "forbidden"),
        (["gh", "repo", "create", "leak-demo", "--public"], "prompt"),
    ]
    details: List[str] = []
    for cmd_tokens, expected_decision in probes:
        res = subprocess.run(
            [codex_bin, "execpolicy", "check", "--rules", str(rules_path), "--", *cmd_tokens],
            text=True,
            capture_output=True,
            timeout=10,
        )
        if res.returncode != 0:
            return (False, [f"codex execpolicy check 失败: {res.stderr.strip()}"])
        try:
            parsed = json.loads(res.stdout)
        except Exception:
            return (False, [f"codex execpolicy 输出无法解析: {res.stdout[:120]}"])
        actual = parsed.get("decision")
        if actual != expected_decision:
            return (
                False,
                [f"命令 `{' '.join(cmd_tokens)}` 期望决策 {expected_decision}，实际得到 {actual}"],
            )
        details.append(f"[PASS] {' '.join(cmd_tokens)} -> {actual}")
    return (True, details)


def apply_codex_harden(
    repo_dir: Path,
    home_dir: Optional[Path] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Install non-destructive `~/.codex/rules/paos-guardrails.rules` without touching `default.rules`."""
    home = home_dir or Path.home()
    rules_src = repo_dir / "templates" / "codex-paos.rules"
    new_text = rules_src.read_text(encoding="utf-8")

    codex_dir = home / ".codex"
    rules_dir = codex_dir / "rules"
    dst = rules_dir / "paos-guardrails.rules"
    backups_dir = codex_dir / "backups"

    current_text = dst.read_text(encoding="utf-8") if dst.is_file() else ""
    diff_lines = list(
        difflib.unified_diff(
            current_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=str(dst) + " (before)",
            tofile=str(dst) + " (after)",
        )
    )
    changed = bool(diff_lines) or not dst.is_file()
    backup_path: Optional[Path] = None

    if not dry_run:
        if dst.is_file() and diff_lines:
            backups_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup_path = backups_dir / f"paos-guardrails-{ts}.rules.bak"
            shutil.copy2(dst, backup_path)
        if changed:
            rules_dir.mkdir(parents=True, exist_ok=True)
            dst.write_text(new_text, encoding="utf-8")

    verify_target = dst if (not dry_run and dst.is_file()) else rules_src
    verified_ok, verify_details = verify_codex_rules_file(verify_target)

    return {
        "dry_run": dry_run,
        "rules_path": str(dst),
        "changed": changed,
        "diff": "".join(diff_lines),
        "backup_path": str(backup_path) if backup_path else None,
        "verified": verified_ok,
        "verify_details": verify_details,
    }


def apply_harden(
    repo_dir: Path,
    home_dir: Path | None = None,
    dry_run: bool = False,
    configure_git: bool = True,
    include_codex: bool = False,
) -> Dict[str, Any]:
    home = home_dir or Path.home()
    claude_dir = home / ".claude"
    hooks_dst = claude_dir / "hooks"
    backups_dir = claude_dir / "backups"
    settings_path = claude_dir / "settings.json"

    current_text = ""
    current_obj: Dict[str, Any] = {}
    if settings_path.is_file():
        current_text = settings_path.read_text(encoding="utf-8")
        if current_text.strip():
            try:
                parsed = json.loads(current_text)
                current_obj = parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError as exc:
                raise ValueError(f"{settings_path} JSON 语法损坏，拒绝覆盖: {exc}") from exc

    merged_obj = merge_claude_settings(current_obj)
    new_text = json.dumps(merged_obj, ensure_ascii=False, indent=2) + "\n"
    diff_lines = list(
        difflib.unified_diff(
            current_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile=str(settings_path) + " (before)",
            tofile=str(settings_path) + " (after)",
        )
    )

    deployed_hooks: List[str] = []
    backup_path: Path | None = None
    gitignore_file: Path | None = None
    gitignore_warning: str | None = None

    if not dry_run:
        hooks_dst.mkdir(parents=True, exist_ok=True)
        for name in HOOK_FILES:
            src = repo_dir / "hooks" / name
            if src.is_file():
                dst = hooks_dst / name
                shutil.copy2(src, dst)
                os.chmod(dst, 0o755)
                deployed_hooks.append(str(dst))

        if settings_path.is_file() and diff_lines:
            backups_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup_path = backups_dir / f"settings-{ts}.json.bak"
            shutil.copy2(settings_path, backup_path)
        elif not settings_path.is_file():
            backups_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            (backups_dir / f"settings-{ts}.empty.bak").write_text("", encoding="utf-8")

        if diff_lines or not settings_path.is_file():
            claude_dir.mkdir(parents=True, exist_ok=True)
            settings_path.write_text(new_text, encoding="utf-8")

        if configure_git:
            try:
                gitignore_file = ensure_global_gitignore(home)
            except OSError as exc:
                gitignore_warning = str(exc)

    codex_res: Optional[Dict[str, Any]] = None
    if include_codex:
        codex_res = apply_codex_harden(repo_dir=repo_dir, home_dir=home, dry_run=dry_run)

    return {
        "dry_run": dry_run,
        "settings_path": str(settings_path),
        "changed": bool(diff_lines) or not settings_path.is_file(),
        "diff": "".join(diff_lines),
        "backup_path": str(backup_path) if backup_path else None,
        "deployed_hooks": deployed_hooks,
        "global_gitignore": str(gitignore_file) if gitignore_file else None,
        "global_gitignore_warning": gitignore_warning,
        "codex": codex_res,
    }


def _write_ignore_rule(target: Path, rule: str = ".claude/settings.local.json") -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = target.read_text(encoding="utf-8").splitlines() if target.is_file() else []
    appended = False
    if rule not in [l.strip() for l in lines]:
        lines.append(rule)
        appended = True
    if appended or not target.is_file():
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def ensure_global_gitignore(home: Path) -> Path:
    """Ensure `.claude/settings.local.json` is excluded in global gitignore."""
    env = os.environ.copy()
    env["HOME"] = str(home)
    existing = ""
    try:
        res = subprocess.run(
            ["git", "config", "--global", "--get", "core.excludesfile"],
            env=env,
            text=True,
            capture_output=True,
            timeout=5,
        )
        if res.returncode == 0 and res.stdout.strip():
            existing = res.stdout.strip()
    except Exception:
        existing = ""

    candidates: List[Path] = []
    if existing:
        candidates.append(Path(os.path.expanduser(existing.replace("~", str(home), 1))))
    candidates.extend([home / ".config" / "git" / "ignore", home / ".gitignore_global"])

    last_err: OSError | None = None
    for target in candidates:
        try:
            _write_ignore_rule(target)
            if not existing or Path(os.path.expanduser(existing.replace("~", str(home), 1))) != target:
                subprocess.run(
                    ["git", "config", "--global", "core.excludesfile", str(target)],
                    env=env,
                    check=False,
                    capture_output=True,
                    timeout=5,
                )
            return target
        except OSError as exc:
            last_err = exc
            continue

    if last_err is not None:
        raise last_err
    return home / ".gitignore_global"


def rollback_settings(home_dir: Path | None = None, include_codex: bool = False) -> Tuple[bool, str]:
    home = home_dir or Path.home()
    msgs: List[str] = []
    any_ok = False

    backups_dir = home / ".claude" / "backups"
    settings_path = home / ".claude" / "settings.json"
    candidates = sorted(backups_dir.glob("settings-*.json.bak")) if backups_dir.is_dir() else []
    empty_sentinels = sorted(backups_dir.glob("settings-*.empty.bak")) if backups_dir.is_dir() else []
    if candidates:
        latest = candidates[-1]
        shutil.copy2(latest, settings_path)
        msgs.append(f"[Claude] 已从 {latest} 恢复 {settings_path}")
        any_ok = True
    elif empty_sentinels and settings_path.is_file():
        settings_path.unlink()
        msgs.append(f"[Claude] 已移除首次生成的配置文件 {settings_path}")
        any_ok = True
    else:
        msgs.append("[Claude] 未找到可回滚的 settings 备份文件。")

    if include_codex:
        codex_bak_dir = home / ".codex" / "backups"
        codex_rules_path = home / ".codex" / "rules" / "paos-guardrails.rules"
        codex_baks = sorted(codex_bak_dir.glob("paos-guardrails-*.rules.bak")) if codex_bak_dir.is_dir() else []
        if codex_baks:
            latest_c = codex_baks[-1]
            codex_rules_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(latest_c, codex_rules_path)
            msgs.append(f"[Codex] 已从 {latest_c} 恢复 {codex_rules_path}")
            any_ok = True
        elif codex_rules_path.is_file():
            codex_rules_path.unlink()
            msgs.append(f"[Codex] 已移除首次生成的门禁规则 {codex_rules_path}")
            any_ok = True
        else:
            msgs.append("[Codex] 未找到可回滚的 paos-guardrails.rules 备份或规则文件。")

    return (any_ok, "\n".join(msgs))
