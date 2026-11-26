"""Isolated process scheduler (`paos run`) & zero-memory Goldfish diff reviewer (`paos review`)."""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .audit import append_audit_event, paos_home, redact_secrets, redact_truncate
from .notify import send_notification

SUPPORTED_ENGINES = ("codex", "claude", "agy")
MAX_REVIEW_DIFF_CHARS = 120_000
LOCKFILE_BASENAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.lock",
    "uv.lock",
    "poetry.lock",
    "composer.lock",
    "Gemfile.lock",
}

GOLDFISH_REVIEW_RUBRIC = """Perform a zero-context cold-start security and correctness review of ONLY the git diff provided on stdin.
Do NOT assume any external context or unstated excuses.
Classify findings strictly into two tiers:
- P0 BLOCKER (`[P0]`): Reproducible bug causing data loss, billing/money miscalculation, auth/privilege/sandbox bypass, secret leak, infinite loop, or crash/broken build. State exact file, line, and reproduction path.
- P1 SUGGESTION (`[P1]`): Non-blocking minor refactor or style note.
On the VERY LAST LINE of your response, output ONLY the exact verdict token:
- Output `[VERDICT: PASS]` if there are zero P0 blockers;
- Otherwise output `[VERDICT: BLOCK_P0]`."""


def detect_engine(preferred: str = "auto", home_dir: Optional[Path] = None) -> Tuple[str, str]:
    """Return `(engine_name, binary_path)` for the requested or first available CLI."""
    home = paos_home(home_dir)
    if preferred and preferred != "auto":
        if preferred not in SUPPORTED_ENGINES:
            raise ValueError(f"不支持的执行引擎: {preferred}（可选: auto, {', '.join(SUPPORTED_ENGINES)}）")
        found = shutil.which(preferred) or (
            str(home / ".local" / "bin" / preferred)
            if (home / ".local" / "bin" / preferred).is_file()
            else None
        )
        if not found:
            raise FileNotFoundError(f"本机未找到可执行命令 `{preferred}`")
        return (preferred, found)

    for eng in ("codex", "claude", "agy"):
        found = shutil.which(eng) or (
            str(home / ".local" / "bin" / eng)
            if (home / ".local" / "bin" / eng).is_file()
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


def _pgroup_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _terminate_pgroup(proc: subprocess.Popen[str], grace_sec: float = 0.3) -> None:
    """Send `SIGTERM` to process group + leader, wait `grace_sec`, then force `SIGKILL` if ANY member remains."""
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
            deadline = time.monotonic() + grace_sec
            while time.monotonic() < deadline:
                if proc.poll() is not None and not _pgroup_alive(proc.pid):
                    return
                time.sleep(0.05)


def exec_with_pgroup_timeout(
    cmd: Sequence[str],
    cwd: Path,
    timeout_sec: int,
    stdin_text: Optional[str] = None,
) -> Tuple[int, str, str, bool]:
    """Execute command in its own process group and sweep the entire tree on timeout or interrupt."""
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
        _terminate_pgroup(proc, grace_sec=0.3)
        try:
            rem_out, rem_err = proc.communicate(timeout=1.0)
            out += rem_out or ""
            err += rem_err or ""
        except Exception:
            pass
    finally:
        if proc.poll() is None or _pgroup_alive(proc.pid):
            _terminate_pgroup(proc, grace_sec=0.15)
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


def _create_isolated_worktree(repo_dir: Path, home: Path, run_id: str) -> Tuple[Path, Path, str, str, bool]:
    """Return `(wt_root_path, wt_exec_subdir, branch_name, base_sha, had_dirty_base)`."""
    wt_parent = home / ".paos" / "worktrees"
    wt_parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    wt_path = wt_parent / f"task-{run_id}"
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

    prefix_r = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", "--show-prefix"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    sub_prefix = prefix_r.stdout.strip() if prefix_r.returncode == 0 else ""

    dirty_r = subprocess.run(
        ["git", "-C", str(repo_dir), "status", "--porcelain"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    had_dirty = bool(dirty_r.stdout.strip()) if dirty_r.returncode == 0 else False

    res = subprocess.run(
        ["git", "-C", str(repo_dir), "worktree", "add", "-b", branch, str(wt_path), base_sha],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if res.returncode != 0:
        raise RuntimeError(f"无法创建隔离 Git Worktree: {res.stderr.strip()}")

    exec_subdir = (wt_path / sub_prefix).resolve() if sub_prefix else wt_path
    return (wt_path, exec_subdir, branch, base_sha, had_dirty)


def _cleanup_empty_worktree(repo_dir: Path, wt_path: Path, branch: str, base_sha: str) -> bool:
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


def _write_log_best_effort(preferred_path: Path, content: str, fallback_prefix: str) -> Optional[str]:
    try:
        preferred_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        preferred_path.write_text(content, encoding="utf-8")
        os.chmod(preferred_path, 0o600)
        return str(preferred_path)
    except OSError:
        try:
            fd, tmp_name = tempfile.mkstemp(prefix=fallback_prefix, suffix=".log")
            os.chmod(tmp_name, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            return tmp_name
        except OSError:
            return None


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
    home = paos_home(home_dir)
    base_dir = (workdir or Path.cwd()).resolve()
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]

    if custom_cmd_override is not None:
        eng_name, bin_path = ("custom", custom_cmd_override[0])
    else:
        eng_name, bin_path = detect_engine(engine, home_dir=home)

    wt_root: Optional[Path] = None
    exec_dir = base_dir
    wt_branch: Optional[str] = None
    wt_base_sha: Optional[str] = None
    had_dirty_base = False
    if use_worktree and not dry_run:
        wt_root, exec_dir, wt_branch, wt_base_sha, had_dirty_base = _create_isolated_worktree(base_dir, home, run_id)

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
    try:
        rc, stdout, stderr, timed_out = exec_with_pgroup_timeout(cmd, cwd=exec_dir, timeout_sec=timeout_sec)
    finally:
        pruned_wt = False
        if use_worktree and wt_root and wt_branch and wt_base_sha:
            pruned_wt = _cleanup_empty_worktree(base_dir, wt_root, wt_branch, wt_base_sha)

    dur_ms = int((time.monotonic() - t0) * 1000)
    safe_stdout = redact_secrets(stdout)
    safe_stderr = redact_secrets(stderr)
    safe_cmd_str = redact_secrets(" ".join(cmd))

    combined = f"# Command: {safe_cmd_str}\n# Exit: {rc} (timeout={timed_out}, {dur_ms}ms)\n\n{safe_stdout}\n{safe_stderr}"
    saved_log = _write_log_best_effort(
        home / ".paos" / "logs" / "runs" / f"{run_id}.log",
        combined,
        fallback_prefix=f"paos-run-{run_id}-",
    )

    status = "timeout" if timed_out else ("ok" if rc == 0 else "failed")
    safe_prompt_head = redact_truncate(prompt, 120)
    append_audit_event(
        event_type="task_run",
        status=status,
        harness=eng_name,
        cwd=str(exec_dir),
        duration_ms=dur_ms,
        summary=f"[{eng_name}] {safe_prompt_head}",
        extra={
            "run_id": run_id,
            "exit_code": rc,
            "log_path": saved_log,
            "worktree": None if pruned_wt else (str(wt_root) if use_worktree and wt_root else None),
        },
        home_dir=home,
    )

    if notify_on_done:
        send_notification(
            title=f"PAOS 任务结束 ({status.upper()})",
            message=f"引擎: {eng_name} | 耗时: {dur_ms / 1000:.1f}s\n任务: {redact_truncate(prompt, 100)}",
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
        "base_repo_had_uncommitted": had_dirty_base,
        "log_path": saved_log,
        "stdout_tail": safe_stdout[-1500:],
        "stderr_tail": safe_stderr[-800:],
    }


def _collect_untracked_patches(repo_dir: Path) -> Tuple[List[str], int]:
    """Collect NUL-delimited untracked files (`-z` handles CJK & spaces accurately)."""
    untracked_r = subprocess.run(
        ["git", "-C", str(repo_dir), "ls-files", "-z", "--others", "--exclude-standard"],
        capture_output=True,
        timeout=10,
    )
    if untracked_r.returncode != 0 or not untracked_r.stdout:
        return ([], 0)

    raw_paths = [p.decode("utf-8", errors="surrogateescape") for p in untracked_r.stdout.split(b"\x00") if p]
    patches: List[str] = []
    skipped = 0
    for rel in raw_paths:
        if os.path.basename(rel) in LOCKFILE_BASENAMES:
            continue
        fpath = repo_dir / rel
        if not fpath.is_file() or fpath.is_symlink():
            continue
        try:
            raw = fpath.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            patches.append(f"diff --git a/{rel} b/{rel}\nnew binary file skipped\n")
            continue
        if len(raw) > 128 * 1024:
            skipped += 1
            patches.append(f"diff --git a/{rel} b/{rel}\nnew file >128KB ({len(raw)} bytes)\n")
            continue
        lines = raw.decode("utf-8", errors="replace").splitlines()
        plus_body = "\n".join(f"+{l}" for l in lines)
        patches.append(
            f"diff --git a/{rel} b/{rel}\nnew file mode 100644\n--- /dev/null\n+++ b/{rel}\n"
            f"@@ -0,0 +1,{len(lines)} @@\n{plus_body}\n"
        )
    return (patches, skipped)


def _strip_lockfile_sections(diff_text: str) -> str:
    """Drop giant lockfile diffs when total diff approaches context budget."""
    if len(diff_text) <= 50_000:
        return diff_text
    kept: List[str] = []
    for chunk in re.split(r"(?=^diff --git )", diff_text, flags=re.M):
        if not chunk.strip():
            continue
        first_line = chunk.splitlines()[0]
        if any(first_line.endswith(f"/{lf}") or first_line.endswith(f" b/{lf}") for lf in LOCKFILE_BASENAMES):
            kept.append(f"{first_line}\n[lockfile diff omitted for review budget]\n")
        else:
            kept.append(chunk)
    return "".join(kept)


def collect_git_diff(repo_dir: Path, base_branch: Optional[str] = None) -> str:
    """Collect tracked + staged + untracked diff (including working-tree edits when `base_branch` is set)."""
    parts: List[str] = []
    if base_branch:
        if base_branch.startswith("-"):
            raise ValueError(f"非法基准分支名称: {base_branch}")
        mb = subprocess.run(
            ["git", "-C", str(repo_dir), "merge-base", base_branch, "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if mb.returncode != 0:
            raise RuntimeError(f"git merge-base {base_branch} HEAD 失败: {mb.stderr.strip()}")
        merge_base = mb.stdout.strip()
        res = subprocess.run(
            ["git", "-C", str(repo_dir), "diff", merge_base, "--"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if res.returncode != 0:
            raise RuntimeError(f"git diff {base_branch} 失败: {res.stderr.strip()}")
        if res.stdout.strip():
            parts.append(res.stdout)
    else:
        staged_r = subprocess.run(["git", "-C", str(repo_dir), "diff", "--cached"], capture_output=True, text=True, timeout=10)
        unstaged_r = subprocess.run(["git", "-C", str(repo_dir), "diff"], capture_output=True, text=True, timeout=10)
        if staged_r.stdout.strip():
            parts.append(staged_r.stdout)
        if unstaged_r.stdout.strip():
            parts.append(unstaged_r.stdout)

    untracked_patches, _ = _collect_untracked_patches(repo_dir)
    parts.extend(untracked_patches)
    return _strip_lockfile_sections("\n".join(parts).strip())


def _evaluate_review_verdict(verdict_stream: str) -> Tuple[bool, bool]:
    """Return `(has_p0, explicit_pass_on_final_line)` anchored strictly to the final non-empty line."""
    non_empty = [l.strip() for l in verdict_stream.splitlines() if l.strip()]
    last_line = non_empty[-1] if non_empty else ""
    final_is_pass = bool(re.match(r"^`?\[VERDICT:\s*PASS\]`?\.?$", last_line))
    final_is_block = bool(re.match(r"^`?\[VERDICT:\s*BLOCK_P0\]`?\.?$", last_line))

    candidate_lines = non_empty[:-1] if (final_is_pass or final_is_block) else non_empty
    body_lines = [
        l
        for l in candidate_lines
        if not l.startswith(">") and "P0 BLOCKER (`[P0]`):" not in l
    ]
    inline_p0 = any(
        re.search(r"(?:^|[\s*#`(]|\d+\.)\[P0\](?!\s*(?:None|无|0\b|N/A))", l)
        for l in body_lines
    )
    has_p0 = final_is_block or inline_p0
    return (has_p0, final_is_pass and not has_p0)


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
    """Zero-memory Goldfish cold-start blind review running in an isolated empty directory."""
    home = paos_home(home_dir)
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

    if len(diff_text) > MAX_REVIEW_DIFF_CHARS and not dry_run:
        return {
            "dry_run": False,
            "engine": engine,
            "status": "diff_too_large",
            "has_p0": True,
            "exit_code": 2,
            "duration_ms": 0,
            "report_path": None,
            "output": (
                f"[PAOS Review Fail-Closed] 待审 Diff 达 {len(diff_text):,} 字符（超过安全盲审上限 {MAX_REVIEW_DIFF_CHARS:,} 字符）。"
                "拒绝静默截断放行，请按子模块拆分提交后再运行 `paos review`。"
            ),
        }

    stdin_payload = f"{GOLDFISH_REVIEW_RUBRIC}\n\n```diff\n{diff_text}\n```\n"
    if custom_reviewer_cmd is not None:
        eng_name, cmd = ("custom", list(custom_reviewer_cmd))
    else:
        eng_name, bin_path = detect_engine(engine, home_dir=home)
        if eng_name == "codex":
            cmd = [bin_path, "exec", "--skip-git-repo-check", "-s", "read-only"]
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
                "3",
            ]
            if xhigh:
                cmd.extend(["--effort", "high"])
            stdin_payload = f"```diff\n{diff_text}\n```\n"
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
            stdin_payload = f"```diff\n{diff_text}\n```\n"

    if dry_run:
        return {
            "dry_run": True,
            "engine": eng_name,
            "repo_dir": str(rdir),
            "diff_chars": len(diff_text),
            "xhigh": xhigh,
            "command": cmd,
        }

    # Execute inside an empty isolated temp dir so target repo's CLAUDE.md/AGENTS.md cannot contaminate cold review!
    with tempfile.TemporaryDirectory(prefix="paos-goldfish-cwd-") as iso_cwd:
        t0 = time.monotonic()
        rc, stdout, stderr, timed_out = exec_with_pgroup_timeout(
            cmd, cwd=Path(iso_cwd), timeout_sec=timeout_sec, stdin_text=stdin_payload
        )
        dur_ms = int((time.monotonic() - t0) * 1000)

    safe_stdout = redact_secrets(stdout.strip())
    safe_stderr = redact_secrets(stderr.strip())
    combined_out = "\n".join(x for x in (safe_stdout, safe_stderr) if x)
    verdict_source = safe_stdout if safe_stdout else safe_stderr
    has_p0, clean_pass = _evaluate_review_verdict(verdict_source)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    saved_rev = _write_log_best_effort(
        home / ".paos" / "logs" / "reviews" / f"review-{ts}.md",
        combined_out + "\n",
        fallback_prefix=f"paos-review-{ts}-",
    )

    if timed_out:
        status, exit_code, verdict_label = ("timeout", 124, "TIMEOUT")
    elif has_p0:
        status, exit_code, verdict_label = ("p0_blocked", 2, "BLOCK_P0")
    elif rc != 0 or not clean_pass:
        status, exit_code, verdict_label = ("failed", rc if rc != 0 else 1, "FAILED")
    else:
        status, exit_code, verdict_label = ("ok", 0, "PASS")

    append_audit_event(
        event_type="code_review",
        status=status,
        harness=eng_name,
        cwd=str(rdir),
        duration_ms=dur_ms,
        summary=f"Goldfish cold review ({verdict_label})",
        extra={"report_path": saved_rev, "xhigh": xhigh, "exit_code": exit_code},
        home_dir=home,
    )

    return {
        "dry_run": False,
        "engine": eng_name,
        "status": status,
        "has_p0": has_p0,
        "exit_code": exit_code,
        "duration_ms": dur_ms,
        "report_path": saved_rev,
        "output": combined_out[-3000:],
    }
