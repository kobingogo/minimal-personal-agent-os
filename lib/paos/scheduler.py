"""Isolated process scheduler (`paos run`) & zero-memory Goldfish diff reviewer (`paos review`)."""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .audit import append_audit_event, redact_secrets
from .notify import send_notification

SUPPORTED_ENGINES = ("codex", "claude", "agy")

GOLDFISH_REVIEW_RUBRIC = """Perform a zero-context cold-start security & correctness review of ONLY the git diff provided via stdin.
Classify findings strictly into two tiers:
- [P0] BLOCKER: Reproducible bug causing data loss, money/billing miscalculation, auth/privilege bypass, secret leak, infinite loop, or broken build/crash. State exact file, line, and reproduction path.
- [P1] SUGGESTION: Non-blocking style, naming, or minor refactor ideas.
If there are NO reproducible P0 blockers, output `[VERDICT: PASS]` on the final line; otherwise output `[VERDICT: BLOCK_P0]` on the final line."""


def detect_engine(preferred: str = "auto") -> Tuple[str, str]:
    """Return `(engine_name, binary_path)` for the requested or first available CLI."""
    if preferred and preferred != "auto":
        if preferred not in SUPPORTED_ENGINES:
            raise ValueError(f"不支持的执行引擎: {preferred}（可选: auto, {', '.join(SUPPORTED_ENGINES)}）")
        found = shutil.which(preferred) or (
            str(Path.home() / ".local" / "bin" / preferred)
            if (Path.home() / ".local" / "bin" / preferred).is_file()
            else None
        )
        if not found:
            raise FileNotFoundError(f"本机未找到可执行命令 `{preferred}`")
        return (preferred, found)

    for eng in ("codex", "claude", "agy"):
        found = shutil.which(eng) or (
            str(Path.home() / ".local" / "bin" / eng)
            if (Path.home() / ".local" / "bin" / eng).is_file()
            else None
        )
        if found:
            return (eng, found)
    raise FileNotFoundError("未找到任何可用的 Agent CLI（需安装 codex、claude 或 agy 之一）")


def build_run_command(
    engine: str,
    bin_path: str,
    prompt: str,
    workdir: Path,
    sandbox_mode: str = "workspace-write",
    max_budget_usd: float = 2.0,
    max_turns: int = 20,
    timeout_sec: int = 600,
    model: Optional[str] = None,
) -> List[str]:
    if engine == "claude":
        cmd = [
            bin_path,
            "-p",
            prompt,
            "--max-budget-usd",
            str(max_budget_usd),
            "--max-turns",
            str(max_turns),
        ]
        if sandbox_mode == "read-only":
            cmd.extend(["--tools", "Read,Grep,Glob"])
        if model:
            cmd.extend(["--model", model])
        return cmd

    if engine == "codex":
        cmd = [bin_path, "exec", "-s", sandbox_mode, "-C", str(workdir)]
        if model:
            cmd.extend(["-m", model])
        cmd.extend(["--", prompt])
        return cmd

    if engine == "agy":
        safe_prompt = (
            f"[STRICT READ-ONLY MODE: Do NOT edit, write, or delete any files] {prompt}"
            if sandbox_mode == "read-only"
            else prompt
        )
        cmd = [bin_path, "-p", safe_prompt, "--print-timeout", f"{timeout_sec}s", "--sandbox"]
        if model:
            cmd.extend(["--model", model])
        return cmd

    raise ValueError(f"Unknown engine: {engine}")


def _create_isolated_worktree(repo_dir: Path, home: Path, run_id: str) -> Tuple[Path, str, str]:
    wt_root = home / ".paos" / "worktrees"
    wt_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    wt_path = wt_root / f"task-{run_id}"
    branch = f"paos/task-{run_id}"
    base_rev = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if base_rev.returncode != 0:
        raise RuntimeError(f"无法读取仓库 HEAD: {base_rev.stderr.strip()}")
    base_sha = base_rev.stdout.strip()

    res = subprocess.run(
        ["git", "-C", str(repo_dir), "worktree", "add", "-b", branch, str(wt_path), base_sha],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if res.returncode != 0:
        raise RuntimeError(f"无法创建隔离 Git Worktree: {res.stderr.strip()}")
    return (wt_path, branch, base_sha)


def _cleanup_empty_worktree(repo_dir: Path, wt_path: Path, branch: str, base_sha: str) -> bool:
    """If the isolated worktree has 0 changes and 0 new commits relative to `base_sha`, prune safely."""
    st = subprocess.run(
        ["git", "-C", str(wt_path), "status", "--porcelain"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    wt_rev = subprocess.run(
        ["git", "-C", str(wt_path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if st.returncode != 0 or wt_rev.returncode != 0:
        return False

    if not st.stdout.strip() and wt_rev.stdout.strip() == base_sha:
        subprocess.run(["git", "-C", str(repo_dir), "worktree", "remove", "--force", str(wt_path)], capture_output=True)
        subprocess.run(["git", "-C", str(repo_dir), "branch", "-D", branch], capture_output=True)
        return True
    return False


def _exec_with_pgroup_timeout(
    cmd: Sequence[str],
    cwd: Path,
    timeout_sec: int,
    stdin_text: Optional[str] = None,
) -> Tuple[int, str, str, bool]:
    """Execute command in its own process group and kill entire tree on timeout."""
    proc = subprocess.Popen(
        list(cmd),
        cwd=str(cwd),
        stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    timed_out = False
    out, err = "", ""
    try:
        out, err = proc.communicate(input=stdin_text, timeout=timeout_sec)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        out = exc.stdout if isinstance(exc.stdout, str) else ((exc.stdout or b"").decode("utf-8", errors="replace"))
        err = exc.stderr if isinstance(exc.stderr, str) else ((exc.stderr or b"").decode("utf-8", errors="replace"))
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(proc.pid, sig)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            try:
                proc.send_signal(sig)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            if sig == signal.SIGTERM:
                try:
                    proc.wait(timeout=0.3)
                    break
                except subprocess.TimeoutExpired:
                    continue
        try:
            rem_out, rem_err = proc.communicate(timeout=1.0)
            out += rem_out or ""
            err += rem_err or ""
        except Exception:
            pass
    finally:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
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


def run_task(
    prompt: str,
    workdir: Optional[Path] = None,
    engine: str = "auto",
    use_worktree: bool = False,
    sandbox_mode: str = "workspace-write",
    max_budget_usd: float = 2.0,
    max_turns: int = 20,
    timeout_sec: int = 600,
    model: Optional[str] = None,
    notify_on_done: bool = False,
    home_dir: Optional[Path] = None,
    dry_run: bool = False,
    custom_cmd_override: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Schedule an isolated, hard-capped Agent run and record its redacted audit log."""
    home = (home_dir or Path.home()).resolve()
    base_dir = (workdir or Path.cwd()).resolve()
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]

    if custom_cmd_override is not None:
        eng_name, bin_path = ("custom", custom_cmd_override[0])
    else:
        eng_name, bin_path = detect_engine(engine)

    exec_dir = base_dir
    wt_branch: Optional[str] = None
    wt_base_sha: Optional[str] = None
    if use_worktree and not dry_run:
        exec_dir, wt_branch, wt_base_sha = _create_isolated_worktree(base_dir, home, run_id)

    cmd = (
        list(custom_cmd_override)
        if custom_cmd_override is not None
        else build_run_command(
            engine=eng_name,
            bin_path=bin_path,
            prompt=prompt,
            workdir=exec_dir,
            sandbox_mode=sandbox_mode,
            max_budget_usd=max_budget_usd,
            max_turns=max_turns,
            timeout_sec=timeout_sec,
            model=model,
        )
    )

    if dry_run:
        return {
            "dry_run": True,
            "run_id": run_id,
            "engine": eng_name,
            "workdir": str(exec_dir),
            "use_worktree": use_worktree,
            "timeout_sec": timeout_sec,
            "max_budget_usd": max_budget_usd,
            "command": [redact_secrets(c) for c in cmd],
        }

    t0 = time.monotonic()
    rc, stdout, stderr, timed_out = _exec_with_pgroup_timeout(cmd, cwd=exec_dir, timeout_sec=timeout_sec)
    dur_ms = int((time.monotonic() - t0) * 1000)

    pruned_wt = False
    if use_worktree and wt_branch and wt_base_sha:
        pruned_wt = _cleanup_empty_worktree(base_dir, exec_dir, wt_branch, wt_base_sha)

    logs_dir = home / ".paos" / "logs" / "runs"
    logs_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    log_path = logs_dir / f"{run_id}.log"
    safe_cmd_str = redact_secrets(" ".join(cmd))
    combined = (
        f"# Command: {safe_cmd_str}\n"
        f"# Exit: {rc} (timeout={timed_out}, {dur_ms}ms)\n\n"
        f"{redact_secrets(stdout)}\n{redact_secrets(stderr)}"
    )
    log_path.write_text(combined, encoding="utf-8")
    os.chmod(log_path, 0o600)

    status = "timeout" if timed_out else ("ok" if rc == 0 else "failed")
    append_audit_event(
        event_type="task_run",
        status=status,
        harness=eng_name,
        cwd=str(exec_dir),
        duration_ms=dur_ms,
        summary=f"[{eng_name}] {prompt[:120]}",
        extra={
            "run_id": run_id,
            "exit_code": rc,
            "log_path": str(log_path),
            "worktree": None if pruned_wt else (str(exec_dir) if use_worktree else None),
        },
        home_dir=home,
    )

    if notify_on_done:
        send_notification(
            title=f"PAOS 任务结束 ({status.upper()})",
            message=f"引擎: {eng_name} | 耗时: {dur_ms / 1000:.1f}s\n任务: {prompt[:100]}",
            home_dir=home,
        )

    return {
        "dry_run": False,
        "run_id": run_id,
        "engine": eng_name,
        "status": status,
        "exit_code": rc,
        "timed_out": timed_out,
        "duration_ms": dur_ms,
        "workdir": None if pruned_wt else str(exec_dir),
        "worktree_branch": None if pruned_wt else wt_branch,
        "worktree_pruned_clean": pruned_wt,
        "log_path": str(log_path),
        "stdout_tail": redact_secrets(stdout)[-1500:],
        "stderr_tail": redact_secrets(stderr)[-800:],
    }


def collect_git_diff(repo_dir: Path, base_branch: Optional[str] = None) -> str:
    if base_branch:
        if base_branch.startswith("-"):
            raise ValueError(f"非法基准分支名称: {base_branch}")
        res = subprocess.run(
            ["git", "-C", str(repo_dir), "diff", f"{base_branch}...HEAD", "--"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if res.returncode != 0:
            raise RuntimeError(f"git diff {base_branch}...HEAD 失败: {res.stderr.strip()}")
        return res.stdout

    staged_r = subprocess.run(["git", "-C", str(repo_dir), "diff", "--cached"], capture_output=True, text=True, timeout=10)
    unstaged_r = subprocess.run(["git", "-C", str(repo_dir), "diff"], capture_output=True, text=True, timeout=10)
    untracked_r = subprocess.run(
        ["git", "-C", str(repo_dir), "ls-files", "--others", "--exclude-standard"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    parts: List[str] = []
    if staged_r.stdout.strip():
        parts.append(staged_r.stdout)
    if unstaged_r.stdout.strip():
        parts.append(unstaged_r.stdout)

    if untracked_r.returncode == 0 and untracked_r.stdout.strip():
        for rel in untracked_r.stdout.splitlines()[:40]:
            fpath = repo_dir / rel
            if not fpath.is_file() or fpath.is_symlink():
                continue
            try:
                raw = fpath.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw[:4096] or len(raw) > 128 * 1024:
                parts.append(f"diff --git a/{rel} b/{rel}\nnew file (binary or >128KB skipped)\n")
                continue
            lines = raw.decode("utf-8", errors="replace").splitlines()
            plus_body = "\n".join(f"+{l}" for l in lines)
            parts.append(
                f"diff --git a/{rel} b/{rel}\nnew file mode 100644\n--- /dev/null\n+++ b/{rel}\n"
                f"@@ -0,0 +1,{len(lines)} @@\n{plus_body}\n"
            )

    return "\n".join(parts).strip()


def run_cold_review(
    repo_dir: Optional[Path] = None,
    base_branch: Optional[str] = None,
    engine: str = "auto",
    xhigh: bool = False,
    timeout_sec: int = 300,
    home_dir: Optional[Path] = None,
    dry_run: bool = False,
    custom_reviewer_cmd: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Zero-memory Goldfish cold-start blind review with Fail-Closed P0/P1 gate."""
    home = (home_dir or Path.home()).resolve()
    rdir = (repo_dir or Path.cwd()).resolve()
    diff_text = collect_git_diff(rdir, base_branch=base_branch)

    if not diff_text.strip() and not dry_run and custom_reviewer_cmd is None:
        return {
            "dry_run": False,
            "status": "skipped_empty_diff",
            "has_p0": False,
            "exit_code": 0,
            "report_path": None,
            "summary": "当前工作区无未提交、未跟踪或分支差异，无需盲审。",
        }

    stdin_payload = f"{GOLDFISH_REVIEW_RUBRIC}\n\n```diff\n{diff_text[:60000]}\n```\n"
    if custom_reviewer_cmd is not None:
        eng_name, cmd = ("custom", list(custom_reviewer_cmd))
    else:
        eng_name, bin_path = detect_engine(engine)
        if eng_name == "codex":
            cmd = [bin_path, "exec", "-s", "read-only", "-C", str(rdir)]
            if xhigh:
                cmd.extend(["-c", 'model_reasoning_effort="xhigh"'])
            cmd.append("-")
        elif eng_name == "claude":
            cmd = [
                bin_path,
                "-p",
                GOLDFISH_REVIEW_RUBRIC,
                "--tools",
                "",
                "--max-budget-usd",
                "1.5",
                "--max-turns",
                "4",
            ]
            stdin_payload = f"```diff\n{diff_text[:60000]}\n```\n"
        else:
            cmd = [
                bin_path,
                "-p",
                GOLDFISH_REVIEW_RUBRIC,
                "--print-timeout",
                f"{timeout_sec}s",
                "--sandbox",
            ]
            if xhigh:
                cmd.extend(["--effort", "xhigh"])
            stdin_payload = f"```diff\n{diff_text[:60000]}\n```\n"

    if dry_run:
        return {
            "dry_run": True,
            "engine": eng_name,
            "repo_dir": str(rdir),
            "diff_chars": len(diff_text),
            "xhigh": xhigh,
            "command": cmd,
        }

    t0 = time.monotonic()
    rc, stdout, stderr, timed_out = _exec_with_pgroup_timeout(
        cmd, cwd=rdir, timeout_sec=timeout_sec, stdin_text=stdin_payload
    )
    dur_ms = int((time.monotonic() - t0) * 1000)

    combined_out = redact_secrets((stdout + "\n" + stderr).strip())
    explicit_pass = bool(re.search(r"\[VERDICT:\s*PASS\]", combined_out))
    explicit_block = bool(re.search(r"\[VERDICT:\s*BLOCK_P0\]", combined_out))
    inline_p0 = bool(re.search(r"(?:^|[\s*#]|\d+\.)\[P0\](?!\s*(?:None|无|0\b|N/A))", combined_out, re.M))
    has_p0 = explicit_block or (inline_p0 and not explicit_pass)

    rev_dir = home / ".paos" / "logs" / "reviews"
    rev_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    rev_path = rev_dir / f"review-{ts}.md"
    rev_path.write_text(combined_out + "\n", encoding="utf-8")
    os.chmod(rev_path, 0o600)

    if timed_out:
        status = "timeout"
        exit_code = 124
        verdict_label = "TIMEOUT"
    elif has_p0:
        status = "p0_blocked"
        exit_code = 2
        verdict_label = "BLOCK_P0"
    elif rc != 0 or not explicit_pass:
        status = "failed"
        exit_code = rc if rc != 0 else 1
        verdict_label = "FAILED"
    else:
        status = "ok"
        exit_code = 0
        verdict_label = "PASS"

    append_audit_event(
        event_type="code_review",
        status=status,
        harness=eng_name,
        cwd=str(rdir),
        duration_ms=dur_ms,
        summary=f"Goldfish cold review ({verdict_label})",
        extra={"report_path": str(rev_path), "xhigh": xhigh, "exit_code": exit_code},
        home_dir=home,
    )

    return {
        "dry_run": False,
        "engine": eng_name,
        "status": status,
        "has_p0": has_p0,
        "exit_code": exit_code,
        "duration_ms": dur_ms,
        "report_path": str(rev_path),
        "output": combined_out[-3000:],
    }
