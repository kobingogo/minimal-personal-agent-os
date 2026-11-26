"""Zero-inbound-port outbound notification bus with mandatory DLP secret redaction."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .audit import append_audit_event, paos_home, real_user_home, redact_secrets, redact_truncate

TupleResult = Tuple[bool, str]


def _load_notify_config(home: Path) -> Dict[str, Any]:
    cfg_file = home / ".paos" / "config.json"
    if not cfg_file.is_file():
        return {}
    try:
        data = json.loads(cfg_file.read_text(encoding="utf-8"))
        return data.get("notify") or {}
    except Exception:
        return {}


def _post_json(url: str, payload: Dict[str, Any], timeout_sec: int = 10) -> TupleResult:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "PAOS-Notify/0.1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            status = getattr(resp, "status", 200)
            resp_body = resp.read(1024).decode("utf-8", errors="replace")
            if not (200 <= status < 300):
                return (False, f"HTTP {status}: {redact_truncate(resp_body, 120)}")
            try:
                parsed = json.loads(resp_body)
                if isinstance(parsed, dict):
                    for code_key in ("code", "StatusCode"):
                        if code_key in parsed and parsed[code_key] != 0:
                            return (False, f"API {code_key}={parsed[code_key]}: {redact_truncate(resp_body, 120)}")
                    if parsed.get("ok") is False:
                        return (False, f"API ok=false: {redact_truncate(resp_body, 120)}")
            except Exception:
                pass
            return (True, f"HTTP {status}: {redact_truncate(resp_body, 120)}")
    except urllib.error.HTTPError as exc:
        err_txt = exc.read(512).decode("utf-8", errors="replace")
        return (False, f"HTTP {exc.code}: {redact_truncate(err_txt, 160)}")
    except Exception as exc:
        return (False, redact_truncate(str(exc), 160))


def _escape_applescript(val: str) -> str:
    return val.replace("\\", "\\\\").replace('"', '\\"').replace("\r", " ").replace("\n", " ")


def send_notification(
    title: str,
    message: str,
    channel: str = "auto",
    home_dir: Optional[Path] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Send an outbound DLP-redacted notification across configured channel(s)."""
    home = paos_home(home_dir)
    cfg = _load_notify_config(home)

    safe_title = redact_secrets(title).strip() or "PAOS 通知"
    safe_msg = redact_secrets(message).strip()

    feishu_url = os.environ.get("PAOS_FEISHU_WEBHOOK") or cfg.get("feishu_webhook") or ""
    tg_token = os.environ.get("PAOS_TELEGRAM_BOT_TOKEN") or cfg.get("telegram_bot_token") or ""
    tg_chat = os.environ.get("PAOS_TELEGRAM_CHAT_ID") or cfg.get("telegram_chat_id") or ""
    generic_url = os.environ.get("PAOS_WEBHOOK_URL") or cfg.get("webhook_url") or ""

    chosen: List[str] = []
    env_ch = os.environ.get("PAOS_NOTIFY_CHANNEL") or cfg.get("default_channel")
    eff_channel = env_ch if (channel == "auto" and env_ch) else channel
    if eff_channel == "auto":
        if platform.system() == "Darwin" and home == real_user_home() and os.environ.get("PAOS_NO_OSASCRIPT") != "1":
            chosen.append("macos")
        if feishu_url:
            chosen.append("feishu")
        if tg_token and tg_chat:
            chosen.append("telegram")
        if generic_url:
            chosen.append("webhook")
        if not chosen:
            chosen.append("stdout")
    else:
        chosen = [c.strip().lower() for c in str(eff_channel).split(",") if c.strip()]

    results: List[Dict[str, Any]] = []
    for ch in chosen:
        if ch in ("lark", "feishu"):
            if not feishu_url:
                results.append({"channel": "feishu", "ok": False, "detail": "未配置 PAOS_FEISHU_WEBHOOK 或 ~/.paos/config.json"})
                continue
            payload = {
                "msg_type": "interactive",
                "card": {
                    "header": {
                        "title": {"tag": "plain_text", "content": safe_title},
                        "template": "blue",
                    },
                    "elements": [
                        {"tag": "markdown", "content": safe_msg},
                    ],
                },
            }
            if dry_run:
                results.append({"channel": "feishu", "ok": True, "detail": "dry-run payload ready", "payload": payload})
            else:
                ok, detail = _post_json(feishu_url, payload)
                results.append({"channel": "feishu", "ok": ok, "detail": detail})

        elif ch == "telegram":
            if not (tg_token and tg_chat):
                results.append({"channel": "telegram", "ok": False, "detail": "未配置 PAOS_TELEGRAM_BOT_TOKEN / CHAT_ID"})
                continue
            api_url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
            payload = {"chat_id": tg_chat, "text": f"*{safe_title}*\n\n{safe_msg}"}
            if dry_run:
                results.append({"channel": "telegram", "ok": True, "detail": "dry-run payload ready"})
            else:
                ok, detail = _post_json(api_url, payload)
                results.append({"channel": "telegram", "ok": ok, "detail": detail})

        elif ch == "webhook":
            if not generic_url:
                results.append({"channel": "webhook", "ok": False, "detail": "未配置 PAOS_WEBHOOK_URL"})
                continue
            payload = {"title": safe_title, "message": safe_msg, "source": "paos"}
            if dry_run:
                results.append({"channel": "webhook", "ok": True, "detail": "dry-run payload ready", "payload": payload})
            else:
                ok, detail = _post_json(generic_url, payload)
                results.append({"channel": "webhook", "ok": ok, "detail": detail})

        elif ch == "macos":
            script = f'display notification "{_escape_applescript(safe_msg[:220])}" with title "{_escape_applescript(safe_title[:64])}"'
            if dry_run:
                results.append({"channel": "macos", "ok": True, "detail": f"dry-run osascript: {script}"})
            else:
                try:
                    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=5)
                    results.append(
                        {
                            "channel": "macos",
                            "ok": r.returncode == 0,
                            "detail": "sent" if r.returncode == 0 else r.stderr.strip()[:120],
                        }
                    )
                except Exception as exc:
                    results.append({"channel": "macos", "ok": False, "detail": str(exc)})

        elif ch == "stdout":
            results.append({"channel": "stdout", "ok": True, "detail": f"[{safe_title}] {safe_msg}"})

        else:
            results.append(
                {
                    "channel": ch,
                    "ok": False,
                    "detail": f"不支持的通知通道 '{ch}'（可选: auto, macos, feishu, telegram, webhook, stdout）",
                }
            )

    overall_ok = bool(results) and all(r["ok"] for r in results) if eff_channel != "auto" else any(r["ok"] for r in results)
    if not dry_run:
        append_audit_event(
            event_type="notify",
            status="ok" if overall_ok else "failed",
            summary=f"{safe_title}: {redact_truncate(safe_msg, 120)}",
            extra={"channels": [r["channel"] for r in results]},
            home_dir=home,
        )

    return {
        "dry_run": dry_run,
        "ok": overall_ok,
        "title": safe_title,
        "message": safe_msg,
        "results": results,
    }
