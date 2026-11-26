"""Zero-daemon native OS scheduler (`launchd` plist on macOS / `crontab` on Linux) with `fcntl.flock`."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import fcntl
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shlex
import subprocess
import sys
import time
from typing import Any, Dict, Iterator, List, Optional

from .audit import append_audit_event, paos_home, real_user_home, redact_secrets, redact_truncate
from .doctor import run_doctor
from .harnesses import clean_harnesses, scan_matrix
from .notify import send_notification
from .resources import resolve_asset
from .scheduler import exec_with_pgroup_timeout, run_task

JOB_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")

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


def _default_cron_path(home: Path) -> str:
    parts = [
        str(home / ".local/bin"),
        str(home / ".bun/bin"),
        str(home / ".volta/bin"),
        str(home / ".cargo/bin"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
    ]
    return ":".join(parts)


def _jobs_registry_path(home: Path) -> Path:
    return home / ".paos" / "cron_jobs.json"


def _load_jobs_registry(home: Path) -> Dict[str, Dict[str, Any]]:
    p = _jobs_registry_path(home)
    data = {k: dict(v) for k, v in BUILTIN_JOBS.items()}
    if p.is_file():
        try:
            custom = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(custom, dict):
                for k, v in custom.items():
                    if not isinstance(v, dict):
                        continue
                    if k in BUILTIN_JOBS:
                        # Security boundary: NEVER allow `cron_jobs.json` to inject arbitrary `cmd` into builtin jobs!
                        for sched_k in ("hour", "minute", "weekday"):
                            if sched_k in v:
                                data[k][sched_k] = v[sched_k]
                    else:
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
    os.chmod(p, 0o600)


def _delete_custom_job_entry(home: Path, name: str) -> None:
    p = _jobs_registry_path(home)
    if not p.is_file():
        return
    try:
        current = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(current, dict) and name in current:
            del current[name]
            p.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass


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

    pkg_parent = str(Path(__file__).resolve().parent.parent)
    prog_args = (
        [sys.executable, "-B", str(paos_bin), "cron", "run-now", safe_name]
        if paos_bin.is_file()
        else [sys.executable, "-B", "-m", "paos", "cron", "run-now", safe_name]
    )
    payload: Dict[str, Any] = {
        "Label": f"com.paos.{safe_name}",
        "ProgramArguments": prog_args,
        "WorkingDirectory": str(home),
        "StartCalendarInterval": cal,
        "ProcessType": "Background",
        "StandardOutPath": str(logs_dir / f"{safe_name}.out.log"),
        "StandardErrorPath": str(logs_dir / f"{safe_name}.err.log"),
        "EnvironmentVariables": {
            "PATH": _default_cron_path(home),
            "HOME": str(home),
            "PYTHONPATH": pkg_parent,
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
    home: Optional[Path] = None,
) -> str:
    safe_name = _validate_job_name(job_name)
    _validate_schedule(hour, minute, weekday)
    dow = str(weekday) if weekday is not None else "*"
    env_prefix = f"PATH={_default_cron_path(home)} " if home else ""
    cmd = f"{env_prefix}{shlex.quote(sys.executable)} -B {shlex.quote(str(paos_bin))} cron run-now {shlex.quote(safe_name)}"
    return f"{int(minute)} {int(hour)} * * {dow} {cmd} {_crontab_tag(safe_name)}"


def _should_touch_live_os_scheduler(home: Path, register_flag: bool) -> bool:
    if not register_flag:
        return False
    if os.environ.get("PAOS_SKIP_LAUNCHCTL") == "1" or os.environ.get("PAOS_SKIP_OS_SCHEDULER") == "1":
        return False
    return home == real_user_home()


def _read_crontab_lines(home: Path, live_os: bool) -> List[str]:
    if not live_os:
        mock_f = home / ".paos" / "crontab.mock"
        return mock_f.read_text(encoding="utf-8").splitlines() if mock_f.is_file() else []
    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
    if r.returncode == 0:
        return r.stdout.splitlines()
    if "no crontab" in (r.stderr or "").lower():
        return []
    raise RuntimeError(f"读取系统 crontab 失败，拒绝覆盖修改: {r.stderr.strip()}")


def _write_crontab_lines(home: Path, lines: List[str], live_os: bool) -> None:
    body = ("\n".join(lines) + "\n") if lines else ""
    if not live_os:
        mock_f = home / ".paos" / "crontab.mock"
        mock_f.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        mock_f.write_text(body, encoding="utf-8")
        return
    subprocess.run(["crontab", "-"], input=body, text=True, check=True, capture_output=True)


def list_cron_jobs(home_dir: Optional[Path] = None, register_launchctl: bool = True) -> List[Dict[str, Any]]:
    home = paos_home(home_dir)
    reg = _load_jobs_registry(home)
    is_mac = platform.system() == "Darwin"
    live_os = _should_touch_live_os_scheduler(home, register_launchctl)

    crontab_lines: List[str] = []
    if not is_mac:
        try:
            crontab_lines = _read_crontab_lines(home, live_os=live_os)
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
    home = paos_home(home_dir)
    reg = _load_jobs_registry(home)

    if job_name in BUILTIN_JOBS and custom_cmd:
        raise ValueError(f"安全限制：不允许为内置任务 '{job_name}' 覆盖自定义 Shell 命令，请使用独立任务名。")
    if job_name not in reg and not custom_cmd:
        raise ValueError(f"新建自定义定时任务 '{job_name}' 必须通过 `--cmd` 指定要执行的命令。")

    base = reg.get(job_name, {"description": f"Custom job {job_name}", "hour": 9, "minute": 0, "weekday": None})
    h = int(hour if hour is not None else base.get("hour", 9))
    m = int(minute if minute is not None else base.get("minute", 0))
    wd = weekday if weekday is not None else base.get("weekday")
    _validate_schedule(h, m, wd)

    spec: Dict[str, Any] = {
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
        or hour is not None
        or minute is not None
        or weekday is not None
    ):
        _save_custom_job(home, job_name, spec)

    live_os = _should_touch_live_os_scheduler(home, register_launchctl)
    if platform.system() == "Darwin":
        pp = plist_path_for(job_name, home)
        plist_bytes = build_launchd_plist(job_name, paos_bin, home, h, m, wd)
        if not dry_run:
            (home / ".paos" / "logs" / "cron").mkdir(parents=True, mode=0o700, exist_ok=True)
            pp.parent.mkdir(parents=True, exist_ok=True)
            pp.write_bytes(plist_bytes)
            if live_os:
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

    line = build_crontab_line(job_name, paos_bin, h, m, wd, home=home)
    if not dry_run:
        existing = [l for l in _read_crontab_lines(home, live_os=live_os) if not _line_has_cron_tag(l, job_name)]
        existing.append(line)
        _write_crontab_lines(home, existing, live_os=live_os)
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
    home = paos_home(home_dir)
    live_os = _should_touch_live_os_scheduler(home, register_launchctl)

    if platform.system() == "Darwin":
        pp = plist_path_for(job_name, home)
        existed = pp.is_file()
        if not dry_run:
            if existed:
                if live_os:
                    uid = os.getuid()
                    subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(pp)], capture_output=True)
                pp.unlink()
            _delete_custom_job_entry(home, job_name)
        return {"dry_run": dry_run, "job": job_name, "removed": existed, "path": str(pp)}

    lines = _read_crontab_lines(home, live_os=live_os)
    filtered = [l for l in lines if not _line_has_cron_tag(l, job_name)]
    removed = len(filtered) != len(lines)
    if not dry_run:
        if removed:
            _write_crontab_lines(home, filtered, live_os=live_os)
        _delete_custom_job_entry(home, job_name)
    return {"dry_run": dry_run, "job": job_name, "removed": removed, "path": "crontab"}


def lock_file_for_job(job_name: str, home: Path) -> Path:
    return home / ".paos" / "locks" / f"{_validate_job_name(job_name)}.flock"


@contextmanager
def acquire_job_flock(lock_file: Path) -> Iterator[bool]:
    """Kernel-managed `fcntl.flock` — auto-released by OS on crash/SIGKILL/reboot, zero PID reuse races."""
    lock_file.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(str(lock_file), os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError:
            acquired = False
        yield acquired
    finally:
        if acquired:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def execute_cron_job_now(
    job_name: str,
    repo_dir: Path,
    home_dir: Optional[Path] = None,
    notify: bool = True,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Run a scheduled job under an OS kernel `fcntl.flock` non-blocking lock."""
    _validate_job_name(job_name)
    home = paos_home(home_dir)
    reg = _load_jobs_registry(home)
    if job_name not in reg:
        raise KeyError(f"未知定时任务 '{job_name}'，可选：{', '.join(sorted(reg.keys()))}")

    lock_path = lock_file_for_job(job_name, home)
    if dry_run:
        return {"dry_run": True, "job": job_name, "lock_file": str(lock_path), "spec": reg[job_name]}

    with acquire_job_flock(lock_path) as got_lock:
        if not got_lock:
            return {"dry_run": False, "job": job_name, "status": "skipped_locked", "summary": "同名定时任务正在运行，跳过重叠触发"}

        t0 = time.monotonic()
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
        elif job_name not in BUILTIN_JOBS and spec.get("cmd"):
            rc, out, err, timed_out = exec_with_pgroup_timeout(
                ["/bin/sh", "-c", str(spec["cmd"])],
                cwd=home,
                timeout_sec=300,
            )
            status = "timeout" if timed_out else ("ok" if rc == 0 else "failed")
            summary = redact_secrets((out + "\n" + err).strip())[-400:] or f"exit={rc}"
        else:
            hb_file = home / ".paos" / "brain" / "HEARTBEAT.md"
            if not hb_file.is_file():
                hb_file = resolve_asset("templates/brain/HEARTBEAT.md", "HEARTBEAT.md")
            inbox_path = home / ".paos" / "brain" / "memory" / "INBOX.md"
            res = run_task(
                prompt=f"只读阅读 {hb_file} 与 {inbox_path.parent}，输出最多 3 条简短巡检提醒（每行必须以 `- ` 开头），不要修改任何文件。",
                workdir=home / ".paos" / "brain" if (home / ".paos" / "brain").is_dir() else repo_dir,
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
                    l.strip()[2:].strip()
                    for l in res["stdout_tail"].splitlines()
                    if re.match(r"^\s*[-*]\s+\S", l)
                ][:3]
                if bullets:
                    inbox_path.parent.mkdir(parents=True, exist_ok=True)
                    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                    with inbox_path.open("a", encoding="utf-8") as f:
                        for b in bullets:
                            f.write(f"- [{stamp}] [Heartbeat] {redact_truncate(b, 180)}\n")

        dur_ms = int((time.monotonic() - t0) * 1000)
        append_audit_event(
            event_type="cron_job",
            status=status,
            summary=f"[{job_name}] {redact_truncate(summary, 160)}",
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
