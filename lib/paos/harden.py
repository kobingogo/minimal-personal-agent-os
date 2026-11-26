"""Idempotent security hardening across Claude Code & Codex CLI using `templates/` as single source of truth."""

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

from .audit import paos_home

HOOK_LAUNCHER_SPECS: Tuple[Tuple[str, str], ...] = (
    ("pre_tool_gate.py", "run_pre_tool_gate_main"),
    ("stop_verify.py", "run_stop_verify_main"),
    ("load_recent_memory.py", "run_session_start_main"),
)
GATE_COMMAND = "~/.claude/hooks/pre_tool_gate.py"


def _dedup_extend(existing: List[Any], additions: List[Any]) -> List[Any]:
    out = list(existing)
    for item in additions:
        if item not in out:
            out.append(item)
    return out


def _load_claude_template(repo_dir: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_dir or Path(__file__).resolve().parent.parent.parent
    tpl = root / "templates" / "claude-user-settings.json"
    return json.loads(tpl.read_text(encoding="utf-8"))


def merge_claude_settings(current: Dict[str, Any], repo_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Non-destructively merge `templates/claude-user-settings.json` into `current`."""
    tpl = _load_claude_template(repo_dir)
    merged = copy.deepcopy(current) if isinstance(current, dict) else {}

    tpl_sb = tpl["sandbox"]
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
    fs["denyRead"] = _dedup_extend(fs.get("denyRead") or [], tpl_sb["filesystem"]["denyRead"])
    fs["denyWrite"] = _dedup_extend(fs.get("denyWrite") or [], tpl_sb["filesystem"]["denyWrite"])

    net = sb.setdefault("network", {})
    if not isinstance(net, dict):
        net = {}
        sb["network"] = net
    if not net.get("allowedDomains"):
        net["allowedDomains"] = list(tpl_sb["network"]["allowedDomains"])

    perms = merged.setdefault("permissions", {})
    if not isinstance(perms, dict):
        perms = {}
        merged["permissions"] = perms
    perms["deny"] = _dedup_extend(perms.get("deny") or [], tpl["permissions"]["deny"])

    hooks = merged.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        merged["hooks"] = hooks
    pre_list = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre_list, list):
        pre_list = []
        hooks["PreToolUse"] = pre_list

    target_matcher = tpl["hooks"]["PreToolUse"][0]["matcher"]
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
                    h["command"] = GATE_COMMAND
                    entry["matcher"] = target_matcher
                    already_wired = True
                    break

    if not already_wired:
        pre_list.append(copy.deepcopy(tpl["hooks"]["PreToolUse"][0]))

    return merged


def verify_codex_rules_file(rules_path: Path) -> Tuple[bool, List[str]]:
    codex_bin = shutil.which("codex")
    if not codex_bin:
        return (True, ["codex CLI 未安装，已仅校验模板文件完整性"])

    checks = [
        (["rm", "-rf", "/"], "forbidden"),
        (["git", "push", "-f", "origin", "main"], "forbidden"),
        (["git", "push", "origin", "--force"], "forbidden"),
        (["git", "reset", "--hard", "HEAD~1"], "forbidden"),
        (["gh", "repo", "create", "leak-demo", "--public"], "prompt"),
    ]
    details: List[str] = []
    for cmd_tokens, expected in checks:
        res = subprocess.run(
            [codex_bin, "execpolicy", "check", "--rules", str(rules_path), "--", *cmd_tokens],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if res.returncode != 0:
            return (False, [f"codex execpolicy check 语法错误: {res.stderr.strip()}"])
        try:
            decision = json.loads(res.stdout).get("decision")
        except Exception:
            decision = None
        if decision != expected:
            return (False, [f"规则决策不匹配 `{' '.join(cmd_tokens)}`: 期望 {expected}, 实际 {decision}"])
        details.append(f"[PASS] {' '.join(cmd_tokens)} -> {decision}")
    return (True, details)


def apply_codex_harden(
    repo_dir: Path,
    home_dir: Optional[Path] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    home = paos_home(home_dir)
    rules_src = repo_dir / "templates" / "codex-paos.rules"
    new_text = rules_src.read_text(encoding="utf-8")

    codex_dir = home / ".codex"
    rules_dir = codex_dir / "rules"
    dst = rules_dir / "paos-guardrails.rules"
    backups_dir = codex_dir / "backups"

    # Validate Starlark template BEFORE touching user's `~/.codex/rules/`!
    verified_ok, verify_details = verify_codex_rules_file(rules_src)
    if not verified_ok:
        raise RuntimeError("Codex Starlark 门禁模板预校验未通过: " + "; ".join(verify_details))

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

    if not dry_run and changed:
        backups_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        if dst.is_file():
            backup_path = backups_dir / f"paos-guardrails-{ts}.rules.bak"
            shutil.copy2(dst, backup_path)
        else:
            (backups_dir / f"paos-guardrails-{ts}.empty.bak").write_text("", encoding="utf-8")
        rules_dir.mkdir(parents=True, exist_ok=True)
        dst.write_text(new_text, encoding="utf-8")

    return {
        "dry_run": dry_run,
        "rules_path": str(dst),
        "changed": changed,
        "diff": "".join(diff_lines),
        "backup_path": str(backup_path) if backup_path else None,
        "verified": verified_ok,
        "verify_details": verify_details,
    }


def _deploy_hook_launchers(repo_dir: Path, hooks_dst: Path) -> List[str]:
    """Write thin executable hook launchers in `~/.claude/hooks/` wired to `repo_dir / 'lib'`."""
    lib_dir = str((repo_dir / "lib").resolve())
    hooks_dst.mkdir(parents=True, exist_ok=True)
    deployed: List[str] = []

    for script_name, entry_fn in HOOK_LAUNCHER_SPECS:
        dst = hooks_dst / script_name
        content = (
            "#!/usr/bin/env python3\n"
            f'"""PAOS managed hook launcher -> {entry_fn}."""\n'
            "import sys\n"
            f"sys.path.insert(0, {lib_dir!r})\n"
            f"from paos.gate import {entry_fn}\n"
            'if __name__ == "__main__":\n'
            f"    sys.exit({entry_fn}())\n"
        )
        dst.write_text(content, encoding="utf-8")
        os.chmod(dst, 0o755)
        deployed.append(str(dst))

    hb_src = repo_dir / "hooks" / "heartbeat-run.sh"
    if hb_src.is_file():
        hb_dst = hooks_dst / "heartbeat-run.sh"
        paos_bin = str((repo_dir / "bin" / "paos").resolve())
        hb_dst.write_text(
            f"#!/usr/bin/env bash\nset -euo pipefail\nexec {paos_bin!r} cron run-now heartbeat \"$@\"\n",
            encoding="utf-8",
        )
        os.chmod(hb_dst, 0o755)
        deployed.append(str(hb_dst))

    return deployed


def apply_harden(
    repo_dir: Path,
    home_dir: Optional[Path] = None,
    dry_run: bool = False,
    configure_git: bool = True,
    include_codex: bool = False,
) -> Dict[str, Any]:
    home = paos_home(home_dir)
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

    merged_obj = merge_claude_settings(current_obj, repo_dir=repo_dir)
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
    backup_path: Optional[Path] = None
    gitignore_file: Optional[Path] = None
    gitignore_warning: Optional[str] = None

    if not dry_run:
        deployed_hooks = _deploy_hook_launchers(repo_dir, hooks_dst)

        if diff_lines or not settings_path.is_file():
            backups_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            if settings_path.is_file():
                backup_path = backups_dir / f"settings-{ts}.json.bak"
                shutil.copy2(settings_path, backup_path)
            else:
                (backups_dir / f"settings-{ts}.empty.bak").write_text("", encoding="utf-8")
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


def _expand_home_prefix(path_str: str, home: Path) -> Path:
    if path_str == "~":
        return home
    if path_str.startswith("~/"):
        return home / path_str[2:]
    return Path(os.path.expanduser(path_str))


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
        candidates.append(_expand_home_prefix(existing, home))
    candidates.extend([home / ".config" / "git" / "ignore", home / ".gitignore_global"])

    last_err: Optional[OSError] = None
    for target in candidates:
        try:
            _write_ignore_rule(target)
            if not existing or _expand_home_prefix(existing, home) != target:
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


def _restore_latest_backup(backups_dir: Path, prefix: str, target_path: Path, label: str) -> Tuple[bool, str]:
    if not backups_dir.is_dir():
        return (False, f"[{label}] 未找到备份目录 {backups_dir}。")

    all_baks = sorted(backups_dir.glob(f"{prefix}-*.bak"), key=lambda p: p.name)
    if not all_baks:
        return (False, f"[{label}] 未找到可回滚的备份文件。")

    latest = all_baks[-1]
    if target_path.is_file():
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        shutil.copy2(target_path, backups_dir / f"pre-rollback-{ts}-{target_path.name}")

    if latest.name.endswith(".empty.bak"):
        if target_path.is_file():
            target_path.unlink()
        latest.unlink(missing_ok=True)
        return (True, f"[{label}] 已回滚移除首次生成的配置文件 {target_path}")

    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(latest, target_path)
    return (True, f"[{label}] 已从 {latest} 恢复 {target_path}")


def rollback_settings(home_dir: Optional[Path] = None, include_codex: bool = False) -> Tuple[bool, str]:
    home = paos_home(home_dir)
    msgs: List[str] = []
    ok_c, msg_c = _restore_latest_backup(
        home / ".claude" / "backups",
        "settings",
        home / ".claude" / "settings.json",
        "Claude",
    )
    msgs.append(msg_c)
    any_ok = ok_c

    if include_codex:
        ok_x, msg_x = _restore_latest_backup(
            home / ".codex" / "backups",
            "paos-guardrails",
            home / ".codex" / "rules" / "paos-guardrails.rules",
            "Codex",
        )
        msgs.append(msg_x)
        any_ok = any_ok or ok_x

    return (any_ok, "\n".join(msgs))
