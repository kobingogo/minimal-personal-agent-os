"""Redacted append-only JSONL audit trail (`~/.paos/logs/audit.jsonl`) & DLP secret scrubber."""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

MAX_AUDIT_BYTES = 5 * 1024 * 1024  # 5 MB rotation threshold

SECRET_REDACT_PATTERNS = [
    re.compile(r"\bsk-[a-zA-Z0-9_-]{12,}"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{16,}"),
    re.compile(r"\bgithub_pat_[a-zA-Z0-9_]{16,}"),
    re.compile(r"\bAIza[a-zA-Z0-9_-]{16,}"),
    re.compile(r"\bxox[baprs]-[a-zA-Z0-9-]{12,}"),
    re.compile(r"\b(?:bot)?\d{8,12}:[A-Za-z0-9_-]{30,}"),
    re.compile(r"https://(?:open\.feishu\.cn|open\.larksuite\.com)/open-apis/bot/v2/hook/[a-zA-Z0-9-]+"),
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"),
    re.compile(r"((?:postgres|postgresql|mysql|mongodb|redis|https?)://[^/\s:@]+:)[^/\s@]+(@)"),
    re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/=-]{16,}", re.I),
    re.compile(
        r"(\b(?:[A-Za-z0-9_]+_)?(?:PASSWORD|PASSWD|API_KEY|APIKEY|AUTH_TOKEN|ACCESS_TOKEN|SECRET_KEY|PRIVATE_KEY|BOT_TOKEN|WEBHOOK_URL|CLIENT_SECRET|ACCESS_KEY|SECRET|TOKEN)\b\s*[:=]\s*['\"]?)[^\s'\"&,;}\]]{4,}",
        re.I,
    ),
]


def redact_secrets(text: str) -> str:
    """Scrub API keys, tokens, DB/HTTP URI passwords, webhooks, and prefixed secret assignments."""
    if not text:
        return text
    out = text
    for pat in SECRET_REDACT_PATTERNS:
        if pat.groups == 2:
            out = pat.sub(r"\1***REDACTED***\2", out)
        elif pat.groups == 1:
            out = pat.sub(r"\1***REDACTED***", out)
        else:
            out = pat.sub("***REDACTED***", out)
    return out


def _redact_obj(val: Any) -> Any:
    if isinstance(val, str):
        return redact_secrets(val)
    if isinstance(val, dict):
        return {str(k): _redact_obj(v) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        return [_redact_obj(v) for v in val]
    return val


def audit_log_path(home_dir: Optional[Path] = None) -> Path:
    home = home_dir or Path(os.environ.get("PAOS_HOME_DIR") or Path.home())
    return Path(home) / ".paos" / "logs" / "audit.jsonl"


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
    """Best-effort redacted audit append (`0o600`); never raises inside restricted hook sandboxes."""
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
            "summary": redact_secrets(summary)[:500],
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
