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
import sys
from typing import Any, Dict, List, Optional, Tuple

from .audit import paos_home
from .resources import resolve_asset

HOOK_LAUNCHER_SPECS: Tuple[Tuple[str, str], ...] = (
    ("pre_tool_gate.py", "run_pre_tool_gate_main"),
    ("stop_verify.py", "run_stop_verify_main"),
    ("load_recent_memory.py", "run_session_start_main"),
)
GATE_COMMAND = "~/.claude/hooks/pre_tool_gate.py"
SESSION_START_COMMAND = "~/.claude/hooks/load_recent_memory.py"
# The gate runs from a copy of the `paos` package inside the protected `~/.claude/hooks/`, not from the
# workspace checkout, so an agent editing the repo cannot rewrite the guard and moving the repo cannot break it.
HOOK_RUNTIME_DIRNAME = "paos_runtime"
# Rules older PAOS templates wrote that no longer belong: `Write(...)` never matches (Edit rules cover
# Write/NotebookEdit), and `Edit(~/.claude/**)` also blocked Claude's own auto memory, skills and agents.
LEGACY_DENY_RULES = {"Edit(~/.claude/**)", "Write(~/.claude/**)"}


def _prune_legacy_deny(rules: List[Any]) -> List[Any]:
    present = {r for r in rules if isinstance(r, str)}
    out: List[Any] = []
    for r in rules:
        if isinstance(r, str):
            if r in LEGACY_DENY_RULES:
                continue
            if r.startswith("Write(") and ("Edit(" + r[len("Write(") :]) in present:
                continue  # no-op twin of an Edit rule
        out.append(r)
    return out


def _find_wired_hook(entries: List[Any], script_names: Tuple[str, ...]) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        inner = entry.get("hooks")
        if not isinstance(inner, list):
            continue
        for h in inner:
            if isinstance(h, dict) and any(k in str(h.get("command") or "") for k in script_names):
                return (entry, h)
    return None


def _dedup_extend(existing: List[Any], additions: List[Any]) -> List[Any]:
    out = list(existing)
    for item in additions:
        if item not in out:
            out.append(item)
    return out


def _load_claude_template(repo_dir: Optional[Path] = None) -> Dict[str, Any]:
    if repo_dir and (repo_dir / "templates" / "claude-user-settings.json").is_file():
        tpl = repo_dir / "templates" / "claude-user-settings.json"
    else:
        tpl = resolve_asset("templates/claude-user-settings.json", "claude-user-settings.json")
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
    perms["deny"] = _prune_legacy_deny(_dedup_extend(perms.get("deny") or [], tpl["permissions"]["deny"]))

    hooks = merged.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        merged["hooks"] = hooks

    for event, script_names, command in (
        ("PreToolUse", ("pre_tool_gate.py", "block-destructive.sh"), GATE_COMMAND),
        ("SessionStart", ("load_recent_memory.py",), SESSION_START_COMMAND),
    ):
        event_list = hooks.setdefault(event, [])
        if not isinstance(event_list, list):
            event_list = []
            hooks[event] = event_list
        tpl_entry = tpl["hooks"][event][0]
        found = _find_wired_hook(event_list, script_names)
        if found is None:
            event_list.append(copy.deepcopy(tpl_entry))
            continue
        entry, h = found
        entry["matcher"] = tpl_entry["matcher"]
        h["command"] = command
        for key, value in tpl_entry["hooks"][0].items():
            if key not in ("type", "command"):
                h[key] = value  # e.g. `onFailure: block`, so a crashed or missing gate stops the call

    return merged


def claude_session_start_wired(home_dir: Optional[Path] = None) -> bool:
    """True when `~/.claude/settings.json` registers the PAOS SessionStart memory hook."""
    settings_path = paos_home(home_dir) / ".claude" / "settings.json"
    try:
        obj = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    hooks = obj.get("hooks") if isinstance(obj, dict) else None
    entries = hooks.get("SessionStart") if isinstance(hooks, dict) else None
    return isinstance(entries, list) and _find_wired_hook(entries, ("load_recent_memory.py",)) is not None


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
    if repo_dir and (repo_dir / "templates" / "codex-paos.rules").is_file():
        rules_src = repo_dir / "templates" / "codex-paos.rules"
    else:
        rules_src = resolve_asset("templates/codex-paos.rules", "codex-paos.rules")
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


def _install_hook_runtime(hooks_dst: Path) -> Path:
    """Copy the active `paos` package into `~/.claude/hooks/paos_runtime/` and return that parent dir.

    `~/.claude/hooks/**` is covered by the sandbox `denyWrite`, the `Edit` deny rules and the gate itself,
    so the code the hooks run cannot be edited by the agent the way a workspace checkout can.
    """
    src_pkg = Path(__file__).resolve().parent
    runtime_parent = hooks_dst / HOOK_RUNTIME_DIRNAME
    staging = hooks_dst / f".{HOOK_RUNTIME_DIRNAME}.tmp-{os.getpid()}"
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(src_pkg, staging / "paos", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    if runtime_parent.exists():
        shutil.rmtree(runtime_parent)
    os.replace(staging, runtime_parent)
    return runtime_parent


def _deploy_hook_launchers(repo_dir: Path, hooks_dst: Path) -> List[str]:
    """Write thin executable hook launchers in `~/.claude/hooks/` that import the protected runtime copy."""
    pkg_parent = str(Path(__file__).resolve().parent.parent)
    py_exe = sys.executable or "/usr/bin/env python3"
    shebang = f"#!{py_exe}\n" if py_exe.startswith("/") else "#!/usr/bin/env python3\n"
    hooks_dst.mkdir(parents=True, exist_ok=True)
    runtime_parent = str(_install_hook_runtime(hooks_dst))
    deployed: List[str] = []

    for script_name, entry_fn in HOOK_LAUNCHER_SPECS:
        dst = hooks_dst / script_name
        content = (
            shebang
            + f'"""PAOS managed hook launcher -> {entry_fn} (protected runtime copy; rerun `paos harden` after upgrading)."""\n'
            "import sys\n"
            "sys.dont_write_bytecode = True\n"
            f"sys.path.insert(0, {runtime_parent!r})\n"
            f"from paos.gate import {entry_fn}\n"
            'if __name__ == "__main__":\n'
            f"    sys.exit({entry_fn}())\n"
        )
        dst.write_text(content, encoding="utf-8")
        os.chmod(dst, 0o755)
        deployed.append(str(dst))

    hb_dst = hooks_dst / "heartbeat-run.sh"
    hb_dst.write_text(
        f"#!/usr/bin/env bash\nset -euo pipefail\nPYTHONPATH={runtime_parent!r} exec {py_exe!r} -B -m paos cron run-now heartbeat \"$@\"\n",
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
