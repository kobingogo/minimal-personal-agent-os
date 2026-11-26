"""Zero-daemon native OS scheduler (`launchd` plist on macOS / `crontab` on Linux) for PAOS."""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

from .audit import append_audit_event, redact_secrets
from .doctor import run_doctor
from .harnesses import clean_harnesses, scan_matrix
from .notify import send_notification
from .scheduler import _exec_with_pgroup_timeout, run_task

JOB_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
STALE_LOCK_MAX_AGE_SEC = 7200  # 2 hours fallback if lock has no pid file

BUILTIN_JOBS: Dict[str, Dict[str, Any]] = {
    "heartbeat": {
        "description": "每日晨间只读巡检 HEARTBEAT.md 并推送最多 3 条摘要至收件箱与通知",
        "hour": 8,
        "minute": 30,
        "weekday": None,
    },
    "weekly-hygiene": {
        "description": "每周日晚自动清理客户端残留临时文件、修复断链并发送五端体检周报",
        "hour": 21,
        "minute": 0,
        "weekday": 0,  # Sunday
    },
}


def _validate_job_name(job_name: str) -> str:
    if not JOB_NAME_RE.match(job_name):
        raise ValueError(f"非法定时任务名 '{job_name}'（仅限字母数字、连字符与下划线，最长 64 字符）")
    return job_name


def _validate_schedule(hour: int, minute: int, weekday: Optional[int]) -> None:
    if not (0 <= hour <= 23):
        raise ValueError(f"hour 必须在 0..23 之间，收到: {hour}")
    if not (0 <= minute <= 59):
        raise ValueError(f"minute 必须在 0..59 之间，收到: {minute}")
    if weekday is not None and not (0 <= weekday <= 6):
        raise ValueError(f"weekday 必须在 0..6 (0=周日) 之间，收到: {weekday}")


def _jobs_registry_path(home: Path) -> Path:
    return home / ".paos" / "cron_jobs.json"


def _load_jobs_registry(home: Path) -> Dict[str, Dict[str, Any]]:
    p = _jobs_registry_path(home)
    data = dict(BUILTIN_JOBS)
    if p.is_file():
        try:
            custom = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(custom, dict):
                for k, v in custom.items():
                    data[k] = v
        except Exception:
            pass
    return data


def _save_custom_job(home: Path, name: str, spec: Dict[str, Any]) -> None:
    p = _jobs_registry_path(home)
    p.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    current: Dict[str, Any] = {}
    if p.is_file():
        try:
            current = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            current = {}
    current[name] = spec
    p.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def plist_path_for(job_name: str, home: Path) -> Path:
    safe_name = _validate_job_name(job_name)
    return home / "Library" / "LaunchAgents" / f"com.paos.{safe_name}.plist"


def build_launchd_plist(
    job_name: str,
    paos_bin: Path,
    home: Path,
    hour: int,
    minute: int,
    weekday: Optional[int] = None,
) -> bytes:
    safe_name = _validate_job_name(job_name)
    _validate_schedule(hour, minute, weekday)
    logs_dir = home / ".paos" / "logs" / "cron"
    cal: Dict[str, int] = {"Hour": int(hour), "Minute": int(minute)}
    if weekday is not None:
        cal["Weekday"] = int(weekday)

    payload: Dict[str, Any] = {
        "Label": f"com.paos.{safe_name}",
        "ProgramArguments": [sys.executable, "-B", str(paos_bin), "cron", "run-now", safe_name],
        "WorkingDirectory": str(home),
        "StartCalendarInterval": cal,
        "ProcessType": "Background",
        "StandardOutPath": str(logs_dir / f"{safe_name}.out.log"),
        "StandardErrorPath": str(logs_dir / f"{safe_name}.err.log"),
        "EnvironmentVariables": {
            "PATH": f"{home / '.local/bin'}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home),
        },
    }
    return plistlib.dumps(payload)


def _crontab_tag(job_name: str) -> str:
    return f"# PAOS-CRON:{_validate_job_name(job_name)}"


def _line_has_cron_tag(line: str, job_name: str) -> bool:
    return line.rstrip().endswith(_crontab_tag(job_name))


def build_crontab_line(
    job_name: str,
    paos_bin: Path,
    hour: int,
    minute: int,
    weekday: Optional[int] = None,
) -> str:
    safe_name = _validate_job_name(job_name)
    _validate_schedule(hour, minute, weekday)
    dow = str(weekday) if weekday is not None else "*"
    cmd = f"{shlex.quote(sys.executable)} -B {shlex.quote(str(paos_bin))} cron run-now {shlex.quote(safe_name)}"
    return f"{int(minute)} {int(hour)} * * {dow} {cmd} {_crontab_tag(safe_name)}"


def _read_crontab_lines_safe() -> List[str]:
    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
    if r.returncode == 0:
        return r.stdout.splitlines()
    if "no crontab" in (r.stderr or "").lower():
        return []
    raise RuntimeError(f"读取系统 crontab 失败，拒绝覆盖修改: {r.stderr.strip()}")


def list_cron_jobs(home_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    home = (home_dir or Path.home()).resolve()
    reg = _load_jobs_registry(home)
    is_mac = platform.system() == "Darwin"

    crontab_lines: List[str] = []
    if not is_mac:
        try:
            crontab_lines = _read_crontab_lines_safe()
        except Exception:
            crontab_lines = []

    out: List[Dict[str, Any]] = []
    for name, spec in sorted(reg.items()):
        if not JOB_NAME_RE.match(name):
            continue
        if is_mac:
            pp = plist_path_for(name, home)
            installed = pp.is_file()
            loc = str(pp)
        else:
            installed = any(_line_has_cron_tag(l, name) for l in crontab_lines)
            loc = "crontab"

        out.append(
            {
                "name": name,
                "installed": installed,
                "hour": spec.get("hour", 8),
                "minute": spec.get("minute", 30),
                "weekday": spec.get("weekday"),
                "description": spec.get("description", ""),
                "custom_cmd": spec.get("cmd"),
                "schedule_location": loc,
            }
        )
    return out


def install_cron_job(
    job_name: str,
    paos_bin: Path,
    hour: Optional[int] = None,
    minute: Optional[int] = None,
    weekday: Optional[int] = None,
    custom_cmd: Optional[str] = None,
    home_dir: Optional[Path] = None,
    dry_run: bool = False,
    register_launchctl: bool = True,
) -> Dict[str, Any]:
    _validate_job_name(job_name)
    home = (home_dir or Path.home()).resolve()
    reg = _load_jobs_registry(home)
    base = reg.get(job_name, {"description": custom_cmd or f"Custom PAOS job {job_name}", "hour": 9, "minute": 0, "weekday": None})

    h = int(hour if hour is not None else base.get("hour", 9))
    m = int(minute if minute is not None else base.get("minute", 0))
    wd = weekday if weekday is not None else base.get("weekday")
    _validate_schedule(h, m, wd)

    spec = {
        "description": base.get("description", ""),
        "hour": h,
        "minute": m,
        "weekday": wd,
    }
    if custom_cmd:
        spec["cmd"] = custom_cmd
        spec["description"] = f"Custom command: {redact_secrets(custom_cmd)}"

    if not dry_run and (
        job_name not in BUILTIN_JOBS
        or custom_cmd
        or hour is not None
        or minute is not None
        or weekday is not None
    ):
        _save_custom_job(home, job_name, spec)

    if platform.system() == "Darwin":
        pp = plist_path_for(job_name, home)
        plist_bytes = build_launchd_plist(job_name, paos_bin, home, h, m, wd)
        if not dry_run:
            (home / ".paos" / "logs" / "cron").mkdir(parents=True, mode=0o700, exist_ok=True)
            pp.parent.mkdir(parents=True, exist_ok=True)
            pp.write_bytes(plist_bytes)
            real_pw_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
            if register_launchctl and home == real_pw_home and os.environ.get("PAOS_SKIP_LAUNCHCTL") != "1":
                uid = os.getuid()
                subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(pp)], capture_output=True)
                subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(pp)], capture_output=True)
        return {
            "dry_run": dry_run,
            "platform": "darwin",
            "job": job_name,
            "path": str(pp),
            "preview": plist_bytes.decode("utf-8"),
        }

    line = build_crontab_line(job_name, paos_bin, h, m, wd)
    if not dry_run:
        existing = [l for l in _read_crontab_lines_safe() if not _line_has_cron_tag(l, job_name)]
        existing.append(line)
        subprocess.run(["crontab", "-"], input="\n".join(existing) + "\n", text=True, check=True, capture_output=True)
    return {
        "dry_run": dry_run,
        "platform": "linux",
        "job": job_name,
        "path": "crontab",
        "preview": line,
    }


def remove_cron_job(
    job_name: str,
    home_dir: Optional[Path] = None,
    dry_run: bool = False,
    register_launchctl: bool = True,
) -> Dict[str, Any]:
    _validate_job_name(job_name)
    home = (home_dir or Path.home()).resolve()
    if platform.system() == "Darwin":
        pp = plist_path_for(job_name, home)
        existed = pp.is_file()
        if existed and not dry_run:
            real_pw_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
            if register_launchctl and home == real_pw_home and os.environ.get("PAOS_SKIP_LAUNCHCTL") != "1":
                uid = os.getuid()
                subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(pp)], capture_output=True)
            pp.unlink()
        return {"dry_run": dry_run, "job": job_name, "removed": existed, "path": str(pp)}

    lines = _read_crontab_lines_safe()
    filtered = [l for l in lines if not _line_has_cron_tag(l, job_name)]
    removed = len(filtered) != len(lines)
    if removed and not dry_run:
        subprocess.run(
            ["crontab", "-"],
            input=("\n".join(filtered) + "\n") if filtered else "",
            text=True,
            check=True,
            capture_output=True,
        )
    return {"dry_run": dry_run, "job": job_name, "removed": removed, "path": "crontab"}


def _acquire_job_lock(lock_dir: Path) -> bool:
    lock_dir.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    for _ in range(2):
        try:
            lock_dir.mkdir(mode=0o700)
            (lock_dir / "pid").write_text(str(os.getpid()), encoding="utf-8")
            return True
        except FileExistsError:
            pid_file = lock_dir / "pid"
            stale = False
            if pid_file.is_file():
                try:
                    owner_pid = int(pid_file.read_text(encoding="utf-8").strip())
                    os.kill(owner_pid, 0)
                except ProcessLookupError:
                    stale = True
                except (ValueError, PermissionError, OSError):
                    stale = False
            else:
                try:
                    if time.time() - lock_dir.stat().st_mtime > STALE_LOCK_MAX_AGE_SEC:
                        stale = True
                except OSError:
                    stale = False
            if stale:
                shutil.rmtree(lock_dir, ignore_errors=True)
                continue
            return False
    return False


def execute_cron_job_now(
    job_name: str,
    repo_dir: Path,
    home_dir: Optional[Path] = None,
    notify: bool = True,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Run a scheduled job under a private `~/.paos/locks` PID-checked atomic lock."""
    _validate_job_name(job_name)
    home = (home_dir or Path.home()).resolve()
    reg = _load_jobs_registry(home)
    if job_name not in reg:
        raise KeyError(f"未知定时任务 '{job_name}'，可选：{', '.join(sorted(reg.keys()))}")

    lock_dir = home / ".paos" / "locks" / f"{job_name}.lock"
    if dry_run:
        return {"dry_run": True, "job": job_name, "lock_dir": str(lock_dir), "spec": reg[job_name]}

    if not _acquire_job_lock(lock_dir):
        return {"dry_run": False, "job": job_name, "status": "skipped_locked", "summary": "同名定时任务正在运行，跳过重叠触发"}

    t0 = time.monotonic()
    try:
        spec = reg[job_name]
        if job_name == "weekly-hygiene":
            cln = clean_harnesses(home_dir=home, min_tmp_age_sec=300, dry_run=False)
            doc = run_doctor(workspace=repo_dir, home_dir=home)
            mat = scan_matrix(home)
            summary = (
                f"健康分: {doc['score']}/100 ({doc['summary']['fail']} 阻断)\n"
                f"清理孤儿文件: {len(cln['removed_orphan_files'])} 个 | 治愈断链: {len(cln['healed_symlinks'])} 个\n"
                f"五端常驻税: ~{mat['totals']['estimated_tokens_across_harnesses']:,} tok"
            )
            status = "ok"
        elif spec.get("cmd"):
            rc, out, err, timed_out = _exec_with_pgroup_timeout(
                ["/bin/sh", "-c", str(spec["cmd"])],
                cwd=home,
                timeout_sec=300,
            )
            status = "timeout" if timed_out else ("ok" if rc == 0 else "failed")
            summary = redact_secrets((out + "\n" + err).strip())[-400:] or f"exit={rc}"
        else:
            hb_file = repo_dir / "HEARTBEAT.md"
            inbox_path = home / ".paos" / "brain" / "memory" / "INBOX.md"
            if not inbox_path.parent.is_dir():
                inbox_path = repo_dir / "memory" / "INBOX.md"
            res = run_task(
                prompt=f"只读阅读 {hb_file}，生成最多 3 条简短巡检提醒（每行 `- ` 开头），不要修改任何代码文件。",
                workdir=repo_dir,
                sandbox_mode="read-only",
                max_budget_usd=1.0,
                max_turns=10,
                timeout_sec=180,
                home_dir=home,
            )
            status = res["status"]
            summary = res["stdout_tail"][:350] or status
            if status == "ok" and res["stdout_tail"].strip():
                bullets = [
                    l.strip().lstrip("-* ").strip()
                    for l in res["stdout_tail"].splitlines()
                    if l.strip()
                ][:3]
                if bullets:
                    inbox_path.parent.mkdir(parents=True, exist_ok=True)
                    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                    with inbox_path.open("a", encoding="utf-8") as f:
                        for b in bullets:
                            f.write(f"- [{stamp}] [Heartbeat] {b[:180]}\n")

        dur_ms = int((time.monotonic() - t0) * 1000)
        append_audit_event(
            event_type="cron_job",
            status=status,
            summary=f"[{job_name}] {summary[:160]}",
            duration_ms=dur_ms,
            home_dir=home,
        )
        if notify:
            send_notification(
                title=f"PAOS 定时巡检完成: {job_name}",
                message=summary,
                home_dir=home,
            )
        return {"dry_run": False, "job": job_name, "status": status, "duration_ms": dur_ms, "summary": summary}
    finally:
        shutil.rmtree(lock_dir, ignore_errors=True)
