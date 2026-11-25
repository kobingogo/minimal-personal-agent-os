"""Idempotent security hardening, deep JSON merge, global gitignore & rollback."""

from __future__ import annotations

import copy
from datetime import datetime
import difflib
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List, Tuple

HOOK_FILES = (
    "pre_tool_gate.py",
    "load_recent_memory.py",
    "stop_verify.py",
    "block-destructive.sh",
    "load-recent-memory.sh",
    "heartbeat-run.sh",
)

REQUIRED_DENY_READ = ["~/.ssh/**", "~/.aws/**", "~/.config/gh/**", "**/.env*"]
REQUIRED_DENY_WRITE = ["~/.claude/**"]
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
    "Write(~/.claude/**)",
    "Edit(~/.claude/**)",
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

    # 1. Sandbox block
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

    # 2. Permissions block
    perms = merged.setdefault("permissions", {})
    if not isinstance(perms, dict):
        perms = {}
        merged["permissions"] = perms
    perms["deny"] = _dedup_extend(list(perms.get("deny") or []), REQUIRED_PERMISSIONS_DENY)

    # 3. PreToolUse 3-level nested hook (idempotent)
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
                "matcher": "Bash|Write|Edit",
                "hooks": [
                    {
                        "type": "command",
                        "command": GATE_COMMAND,
                    }
                ],
            }
        )

    return merged


def apply_harden(
    repo_dir: Path,
    home_dir: Path | None = None,
    dry_run: bool = False,
    configure_git: bool = True,
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
            current_obj = json.loads(current_text)

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

        if diff_lines or not settings_path.is_file():
            claude_dir.mkdir(parents=True, exist_ok=True)
            settings_path.write_text(new_text, encoding="utf-8")

        if configure_git:
            try:
                gitignore_file = ensure_global_gitignore(home)
            except OSError as exc:
                gitignore_warning = str(exc)

    return {
        "dry_run": dry_run,
        "settings_path": str(settings_path),
        "changed": bool(diff_lines) or not settings_path.is_file(),
        "diff": "".join(diff_lines),
        "backup_path": str(backup_path) if backup_path else None,
        "deployed_hooks": deployed_hooks,
        "global_gitignore": str(gitignore_file) if gitignore_file else None,
        "global_gitignore_warning": gitignore_warning,
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


def rollback_settings(home_dir: Path | None = None) -> Tuple[bool, str]:
    home = home_dir or Path.home()
    backups_dir = home / ".claude" / "backups"
    settings_path = home / ".claude" / "settings.json"
    if not backups_dir.is_dir():
        return (False, "未找到备份目录 ~/.claude/backups/。")

    candidates = sorted(backups_dir.glob("settings-*.json.bak"))
    if not candidates:
        return (False, "未找到任何可回滚的 settings 备份文件。")

    latest = candidates[-1]
    shutil.copy2(latest, settings_path)
    return (True, f"已从 {latest} 恢复 {settings_path}")
