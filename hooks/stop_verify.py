#!/usr/bin/env python3
"""Optional project-scoped Stop verification hook with Stuck-Cap loop breaker.

Prevents two classic Stop-hook disasters:
1. Running slow test suites on pure Q&A turns when no files changed;
2. Trapping the agent in an infinite retry loop when tests keep failing
   (caps automated retries at MAX_STOP_RETRIES per session, then yields to human).

Configure in PROJECT `.claude/settings.json` (never user-global!), and set
`PAOS_VERIFY_CMD` (e.g. `pytest -q` or `npm test`).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_STOP_RETRIES = int(os.environ.get("PAOS_MAX_STOP_RETRIES", "2"))
VERIFY_TIMEOUT_SEC = int(os.environ.get("PAOS_VERIFY_TIMEOUT", "45"))


def state_file_for(session_id: str) -> Path:
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"paos-stop-retries-{digest}.count"


def has_git_changes(cwd: Path) -> bool:
    try:
        res = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(cwd),
            text=True,
            capture_output=True,
            timeout=5,
        )
        if res.returncode != 0:
            return False
        return bool(res.stdout.strip())
    except Exception:
        return False


def main() -> int:
    verify_cmd = os.environ.get("PAOS_VERIFY_CMD", "").strip()
    if not verify_cmd:
        return 0

    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        payload = {}

    cwd = Path(payload.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    session_id = str(payload.get("session_id") or cwd)
    stop_active = bool(payload.get("stop_hook_active", False))

    if not has_git_changes(cwd):
        return 0

    sf = state_file_for(session_id)
    retries = 0
    if stop_active and sf.is_file():
        try:
            retries = int(sf.read_text(encoding="utf-8").strip() or "0")
        except ValueError:
            retries = 0

    if retries >= MAX_STOP_RETRIES:
        sf.unlink(missing_ok=True)
        sys.stderr.write(
            f"[PAOS Stuck-Cap 熔断] 自动验证已连续失败 {retries} 次，停止自动重试并交回人工判断。\n"
        )
        return 0

    try:
        proc = subprocess.run(
            verify_cmd,
            shell=True,
            cwd=str(cwd),
            text=True,
            capture_output=True,
            timeout=VERIFY_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        sf.write_text(str(retries + 1), encoding="utf-8")
        sys.stderr.write(f"[PAOS Stop 验证超时] `{verify_cmd}` 超过 {VERIFY_TIMEOUT_SEC}s。\n")
        return 2

    if proc.returncode == 0:
        sf.unlink(missing_ok=True)
        return 0

    sf.write_text(str(retries + 1), encoding="utf-8")
    tail = (proc.stdout + "\n" + proc.stderr).strip()[-1200:]
    sys.stderr.write(
        f"[PAOS Stop 验证未通过 ({retries + 1}/{MAX_STOP_RETRIES})] `{verify_cmd}` 失败：\n{tail}\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
