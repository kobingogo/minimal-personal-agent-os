"""Shared OS home helpers, DLP secret scrubber, and 5MB-rotating JSONL audit log."""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import pwd
import re
from typing import Any, Dict, List, Optional, Tuple

MAX_AUDIT_BYTES = 5 * 1024 * 1024  # 5 MB rotation threshold

SECRET_PATTERNS_LABELED: List[Tuple[str, re.Pattern[str]]] = [
    (
        "PEM Private Key",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
    ),
    ("PEM Private Key Header", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("OpenAI/Anthropic Key", re.compile(r"\bsk-[a-zA-Z0-9_-]{12,}")),
    ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub/GitLab/HF/NPM Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{16,}|\bgithub_pat_[a-zA-Z0-9_]{16,}|\bglpat-[a-zA-Z0-9_-]{16,}|\bhf_[a-zA-Z0-9]{20,}|\bnpm_[a-zA-Z0-9]{20,}")),
    ("Google API Key", re.compile(r"\bAIza[a-zA-Z0-9_-]{16,}")),
    ("Slack/Telegram Token", re.compile(r"\bxox[baprs]-[a-zA-Z0-9-]{12,}|\b(?:bot)?\d{8,12}:[A-Za-z0-9_-]{30,}")),
    (
        "IM Webhook URL",
        re.compile(
            r"https://(?:open\.feishu\.cn|open\.larksuite\.com)/open-apis/bot/v2/hook/[a-zA-Z0-9-]+|"
            r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+|"
            r"https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9-]+|"
            r"https://oapi\.dingtalk\.com/robot/send\?access_token=[a-zA-Z0-9_-]+|"
            r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"
        ),
    ),
    ("URI Password", re.compile(r"((?:postgres|postgresql|mysql|mongodb|redis|https?)://[^/\s:@]+:)[^/\s@]+(@)")),
    ("Bearer Token", re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/=-]{12,}", re.I)),
    (
        "Secret Assignment / JSON Key",
        re.compile(
            r"(\b(?:[A-Za-z0-9_-]+[-_])?(?:PASSWORD|PASSWD|API[-_]?KEY|AUTH[-_]?TOKEN|ACCESS[-_]?TOKEN|SECRET[-_]?KEY|PRIVATE[-_]?KEY|BOT[-_]?TOKEN|WEBHOOK[-_]?URL|CLIENT[-_]?SECRET|ACCESS[-_]?KEY|SECRET|TOKEN)\b['\"]?\s*[:=]\s*['\"]?)[^\s'\"&,;}\]]{4,}",
            re.I,
        ),
    ),
]


def paos_home(home_dir: Optional[Path] = None) -> Path:
    """Resolve active PAOS target home directory (`home_dir` > `PAOS_HOME_DIR` > `Path.home()`)."""
    if home_dir is not None:
        return Path(home_dir).resolve()
    env_home = os.environ.get("PAOS_HOME_DIR")
    if env_home:
        return Path(env_home).resolve()
    return Path.home().resolve()


def real_user_home() -> Path:
    """Resolve real OS account home via `/etc/passwd`, safely falling back in rootless containers."""
    try:
        return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    except (KeyError, OSError):
        return Path.home().resolve()


def redact_secrets(text: str) -> str:
    """Scrub API keys, PEM blocks, JSON/env secret values, URI passwords, and webhook URLs."""
    if not text:
        return text
    out = text
    for _label, pat in SECRET_PATTERNS_LABELED:
        if pat.groups == 2:
            out = pat.sub(r"\1***REDACTED***\2", out)
        elif pat.groups == 1:
            out = pat.sub(r"\1***REDACTED***", out)
        else:
            out = pat.sub("***REDACTED***", out)
    return out


def redact_truncate(text: str, max_chars: int) -> str:
    """Always redact on the FULL string BEFORE slicing so boundary-straddling tokens never leak."""
    if not text:
        return ""
    return redact_secrets(text)[:max_chars]


def _redact_obj(val: Any) -> Any:
    if isinstance(val, str):
        return redact_secrets(val)
    if isinstance(val, dict):
        return {str(k): _redact_obj(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [_redact_obj(v) for v in val]
    return val


def scan_text_for_secrets(text: str) -> List[str]:
    """Return redacted line-level secret alerts (`第 N 行命中疑似「...」`) without echoing values."""
    hits: List[str] = []
    if "-----BEGIN" in text and "PRIVATE KEY-----" in text:
        hits.append("命中疑似「PEM Private Key」（内容已脱敏隐藏）")
    for idx, line in enumerate(text.splitlines(), 1):
        for label, pat in SECRET_PATTERNS_LABELED:
            if label == "PEM Private Key":
                continue
            if pat.search(line):
                hits.append(f"第 {idx} 行命中疑似「{label}」（内容已脱敏隐藏）")
                break
    return hits


def audit_log_path(home_dir: Optional[Path] = None) -> Path:
    return paos_home(home_dir) / ".paos" / "logs" / "audit.jsonl"


def append_audit_event(
    event_type: str,
    status: str,
    summary: str,
    harness: str = "paos",
    cwd: Optional[str] = None,
    duration_ms: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
    home_dir: Optional[Path] = None,
) -> Optional[Path]:
    """Best-effort redacted audit append (`0o600` + 5MB rotation); never raises inside sandboxes."""
    try:
        log_file = audit_log_path(home_dir)
        log_file.parent.mkdir(parents=True, mode=0o700, exist_ok=True)

        if log_file.is_file() and log_file.stat().st_size > MAX_AUDIT_BYTES:
            bak = log_file.with_suffix(".jsonl.1")
            if bak.exists():
                bak.unlink()
            log_file.rename(bak)

        record: Dict[str, Any] = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "event": event_type,
            "status": status,
            "harness": harness,
            "cwd": cwd or os.getcwd(),
            "summary": redact_truncate(summary, 500),
        }
        if duration_ms is not None:
            record["duration_ms"] = int(duration_ms)
        if extra:
            record["meta"] = _redact_obj(extra)

        with log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        os.chmod(log_file, 0o600)
        return log_file
    except OSError:
        return None


def read_audit_events(
    home_dir: Optional[Path] = None,
    limit: int = 30,
    blocks_only: bool = False,
    event_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    log_file = audit_log_path(home_dir)
    if not log_file.is_file():
        return []
    out: List[Dict[str, Any]] = []
    for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except Exception:
            continue
        if blocks_only and obj.get("status") not in ("blocked", "tripped", "p0_blocked", "failed", "timeout"):
            continue
        if event_filter and obj.get("event") != event_filter:
            continue
        out.append(obj)
    return out[-max(1, limit) :]
