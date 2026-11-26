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

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

MAX_STOP_RETRIES = int(os.environ.get("PAOS_MAX_STOP_RETRIES", "2"))
VERIFY_TIMEOUT_SEC = int(os.environ.get("PAOS_VERIFY_TIMEOUT", "45"))


def _paos_home() -> Path:
    return Path(os.environ.get("PAOS_HOME_DIR") or Path.home())


def state_file_for(session_id: str) -> Path:
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]
    st_dir = _paos_home() / ".paos" / "state"
    st_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    return st_dir / f"stop-retries-{digest}.count"


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


def _run_shell_pgroup(cmd: str, cwd: Path, timeout_sec: int) -> tuple[int, str, str, bool]:
    proc = subprocess.Popen(
        cmd,
        shell=True,
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    timed_out = False
    out, err = "", ""
    try:
        out, err = proc.communicate(timeout=timeout_sec)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        out = exc.stdout if isinstance(exc.stdout, str) else ((exc.stdout or b"").decode("utf-8", errors="replace"))
        err = exc.stderr if isinstance(exc.stderr, str) else ((exc.stderr or b"").decode("utf-8", errors="replace"))
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(proc.pid, sig)
            except OSError:
                pass
            try:
                proc.send_signal(sig)
            except OSError:
                pass
            if sig == signal.SIGTERM:
                try:
                    proc.wait(timeout=0.3)
                    break
                except subprocess.TimeoutExpired:
                    continue
        try:
            ro, re_txt = proc.communicate(timeout=1.0)
            out += ro or ""
            err += re_txt or ""
        except Exception:
            pass
    finally:
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass
        try:
            proc.wait(timeout=1.0)
        except Exception:
            pass
    return (proc.returncode if not timed_out else 124, out or "", err or "", timed_out)


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
        try:
            lf = _paos_home() / ".paos" / "logs" / "audit.jsonl"
            lf.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            rec = {
                "ts": datetime.now().isoformat(timespec="seconds"),
                "event": "stuck_cap",
                "status": "tripped",
                "harness": "claude",
                "cwd": str(cwd),
                "summary": f"Stop verification failed {retries} times consecutively; yielded to human",
            }
            with lf.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            os.chmod(lf, 0o600)
        except Exception:
            pass
        sys.stderr.write(
            f"[PAOS Stuck-Cap 熔断] 自动验证已连续失败 {retries} 次，停止自动重试并交回人工判断。\n"
        )
        return 0

    rc, stdout, stderr, timed_out = _run_shell_pgroup(verify_cmd, cwd=cwd, timeout_sec=VERIFY_TIMEOUT_SEC)
    if timed_out:
        sf.write_text(str(retries + 1), encoding="utf-8")
        sys.stderr.write(f"[PAOS Stop 验证超时] `{verify_cmd}` 超过 {VERIFY_TIMEOUT_SEC}s。\n")
        return 2

    if rc == 0:
        sf.unlink(missing_ok=True)
        return 0

    sf.write_text(str(retries + 1), encoding="utf-8")
    tail = (stdout + "\n" + stderr).strip()[-1200:]
    sys.stderr.write(
        f"[PAOS Stop 验证未通过 ({retries + 1}/{MAX_STOP_RETRIES})] `{verify_cmd}` 失败：\n{tail}\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
