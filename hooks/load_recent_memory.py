#!/usr/bin/env python3
"""SessionStart dynamic memory loader with strict byte-budget protection.

Injects a compact operational snapshot (<= 3,800 chars, well below Claude Code's
10,000-char SessionStart truncation limit) without mutating static CLAUDE.md
(preserving Prompt Cache).
"""

from __future__ import annotations

from collections import Counter
from datetime import date, timedelta
from pathlib import Path
import os
import re
import sys

MAX_OUTPUT_CHARS = 3800
TAG_RE = re.compile(r"\[tag:([a-zA-Z0-9_-]+)\]")


def read_lines_safe(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def build_snapshot(root: Path, today: date | None = None) -> str:
    today = today or date.today()
    yesterday = today - timedelta(days=1)
    mem_dir = root / "memory"
    if not mem_dir.is_dir():
        return ""

    out: list[str] = [f"=== Personal OS 开机状态 ({today.isoformat()}) ==="]

    # 1. Active TODAY.md focus
    today_lines = [l for l in read_lines_safe(mem_dir / "TODAY.md") if l.strip()]
    if today_lines:
        out.append("--- 今日聚焦 (TODAY.md) ---")
        out.extend(today_lines[:25])

    # 2. INBOX count
    inbox_lines = read_lines_safe(mem_dir / "INBOX.md")
    inbox_items = sum(1 for l in inbox_lines if re.match(r"^\s*-\s+\S", l))
    out.append(f"--- 待分诊收件箱 (INBOX.md): {inbox_items} 条 ---")

    # 3. Yesterday & Today daily logs (tail)
    for d in (yesterday, today):
        d_str = d.isoformat()
        daily_lines = [l for l in read_lines_safe(mem_dir / "daily" / f"{d_str}.md") if l.strip()]
        if daily_lines:
            out.append(f"--- 每日日志 ({d_str}) ---")
            out.extend(daily_lines[-20:])

    # 4. Recurring learnings ready for promotion
    learn_text = "\n".join(read_lines_safe(mem_dir / "learnings.md"))
    tags = Counter(TAG_RE.findall(learn_text))
    ready = [f"{t}({c}次)" for t, c in tags.most_common(5) if c >= 2]
    if ready:
        out.append(f"--- 进化提醒：检测到复发纠偏标签 {', '.join(ready)}，周末可运行 /promote 审阅晋升 ---")

    joined = "\n".join(out)
    if len(joined) > MAX_OUTPUT_CHARS:
        joined = joined[: MAX_OUTPUT_CHARS - 40] + "\n...[已按预算截断，详见 memory/ 目录]"
    return joined + "\n"


def main() -> int:
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    snap = build_snapshot(root)
    if snap:
        sys.stdout.write(snap)
    return 0


if __name__ == "__main__":
    sys.exit(main())
