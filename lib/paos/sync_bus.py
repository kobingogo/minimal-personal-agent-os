"""Unified Cross-Harness Memory & Rule Compiler (`~/.paos/brain/` -> Claude/Codex/Antigravity/Cursor).

Uses non-destructive `<!-- PAOS:BEGIN --> ... <!-- PAOS:END -->` managed blocks so user-authored
instructions (e.g. `~/.codex/AGENTS.md` `@RTK.md` or `~/.gemini/GEMINI.md` personal rules) are
preserved 100% intact, even when rules contain regex/backslash escapes.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import difflib
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Optional, Sequence, Tuple

BEGIN_MARKER = "<!-- PAOS:BEGIN -->"
END_MARKER = "<!-- PAOS:END -->"
MANAGED_BLOCK_RE = re.compile(
    re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER) + r"\n?",
    re.S,
)
TAG_RE = re.compile(r"\[tag:([a-zA-Z0-9_-]+)\]")
PROMOTED_RE = re.compile(r"\[promoted:")
ALLOWED_SYNC_TARGETS = ("claude", "codex", "antigravity", "cursor")

DEFAULT_CORE_RULES = """# PAOS 跨端共享核心工程契约 (CORE_RULES)
- 结论先行，简洁直接；执行删除、覆盖或外发操作前先说明影响并等待确认。
- 一模型一坑：先给 3 行可检验验收标准再动手；同一报错连续修 2 次未过立即停机换思路。
- 严守上下文信噪比：长期记忆索引死守 <=200 行指针，新踩坑先记入 `learnings.md` 草稿池。
"""

DEFAULT_SHARED_USER = """# 个人季度主线与边界 (USER)
- 主线 1：聚焦核心产品与自动化工程交付，砍掉偏离主线的玩具需求。
- 主线 2：沉淀高复用确定性脚本与开源资产（钩子与脚本优先于纯文字叮嘱）。
- 禁区边界：个人财务、主账号根私钥与未脱敏凭证严禁混入编码工作区。
"""


def brain_root(home_dir: Optional[Path] = None) -> Path:
    home = (home_dir or Path.home()).resolve()
    return home / ".paos" / "brain"


def init_brain(home_dir: Optional[Path] = None, seed_workspace: Optional[Path] = None) -> Dict[str, Any]:
    """Initialize `~/.paos/brain/` shared state directory idempotently."""
    home = (home_dir or Path.home()).resolve()
    broot = brain_root(home)
    mem = broot / "memory"
    (mem / "daily").mkdir(parents=True, exist_ok=True)
    (mem / "topics").mkdir(parents=True, exist_ok=True)

    created: List[str] = []

    def _ensure_file(dst: Path, fallback_content: str, seed_rel: Optional[str] = None) -> None:
        if dst.is_file():
            return
        if seed_workspace and seed_rel and (seed_workspace / seed_rel).is_file():
            shutil.copy2(seed_workspace / seed_rel, dst)
        else:
            dst.write_text(fallback_content, encoding="utf-8")
        created.append(str(dst))

    _ensure_file(broot / "CORE_RULES.md", DEFAULT_CORE_RULES)
    _ensure_file(broot / "USER.md", DEFAULT_SHARED_USER, "USER.md")
    _ensure_file(mem / "TODAY.md", "# 今日聚焦 (最多 3 件 P0)\n\n- [ ] 运行 `paos status` 查看五端状态\n", "memory/TODAY.md")
    _ensure_file(mem / "INBOX.md", "# 全局待分诊收件箱 (INBOX)\n\n", "memory/INBOX.md")
    _ensure_file(
        mem / "MEMORY.md",
        "# 跨客户端共享记忆总索引 (<=200 行硬上限)\n\n- 踩坑与防呆记录见 `~/.paos/brain/memory/learnings.md`\n",
        "memory/MEMORY.md",
    )
    _ensure_file(
        mem / "learnings.md",
        "# 待审校纠偏草稿箱 (Learnings)\n\n<!-- 格式: - [YYYY-MM-DD] [tag:类别] 现象 -> 根因 -> 防复发动作 -->\n",
        "memory/learnings.md",
    )

    return {"brain_dir": str(broot), "created_files": created}


def _extract_active_summary(broot: Path) -> Dict[str, str]:
    core_txt = (broot / "CORE_RULES.md").read_text(encoding="utf-8").strip() if (broot / "CORE_RULES.md").is_file() else ""
    today_p = broot / "memory" / "TODAY.md"
    today_lines: List[str] = []
    if today_p.is_file():
        today_lines = [
            l.strip()
            for l in today_p.read_text(encoding="utf-8").splitlines()
            if l.strip().startswith("- [ ]")
        ][:3]

    learn_p = broot / "memory" / "learnings.md"
    hot_tags: List[str] = []
    if learn_p.is_file():
        counts: Counter[str] = Counter()
        for line in learn_p.read_text(encoding="utf-8").splitlines():
            if not PROMOTED_RE.search(line):
                counts.update(dict.fromkeys(TAG_RE.findall(line)).keys())
        hot_tags = [f"{t}({c}次)" for t, c in counts.most_common(3) if c >= 2]

    return {
        "core_rules": core_txt,
        "today_summary": "\n".join(today_lines) if today_lines else "- (暂无未完成 P0，可通过 `paos capture` 或编辑 `~/.paos/brain/memory/TODAY.md` 设定)",
        "hot_tags": ", ".join(hot_tags),
    }


def _upsert_managed_block(existing: str, block_inner: str, remove: bool = False) -> str:
    if remove:
        if BEGIN_MARKER not in existing:
            return existing
        cleaned = MANAGED_BLOCK_RE.sub("", existing).rstrip()
        return (cleaned + "\n") if cleaned else ""

    wrapped = f"{BEGIN_MARKER}\n{block_inner.rstrip()}\n{END_MARKER}\n"
    if MANAGED_BLOCK_RE.search(existing):
        # Lambda avoids Python `re.sub` parsing `\d`, `\s`, `\u`, `\1` escapes inside user rule text!
        return MANAGED_BLOCK_RE.sub(lambda _m: wrapped, existing, count=1)

    base = existing.rstrip()
    if not base:
        return wrapped
    return f"{base}\n\n{wrapped}"


def sync_brain(
    home_dir: Optional[Path] = None,
    targets: Optional[Sequence[str]] = None,
    dry_run: bool = False,
    remove: bool = False,
) -> Dict[str, Any]:
    """Compile `~/.paos/brain/` into Claude, Codex, Antigravity, and Cursor non-destructively."""
    home = (home_dir or Path.home()).resolve()
    broot = brain_root(home)
    if not remove and not broot.is_dir():
        if not dry_run:
            init_brain(home)

    if targets:
        chosen = [t.strip().lower() for t in targets if t.strip()]
        invalid = [t for t in chosen if t not in ALLOWED_SYNC_TARGETS]
        if invalid:
            raise ValueError(f"不支持的同步目标: {', '.join(invalid)}（可选: {', '.join(ALLOWED_SYNC_TARGETS)}）")
    else:
        chosen = [
            t for t in ALLOWED_SYNC_TARGETS if (home / (f".{t}" if t != "antigravity" else ".gemini")).exists()
        ]
        if not chosen:
            chosen = ["claude", "codex"]

    summary = _extract_active_summary(broot) if broot.is_dir() else {
        "core_rules": DEFAULT_CORE_RULES.strip(),
        "today_summary": "- [ ] 运行 `paos status` 查看五端状态",
        "hot_tags": "",
    }
    hot_line = f"\n- 待晋升复发坑点提醒：{summary['hot_tags']}" if summary["hot_tags"] else ""

    compiled_blocks: Dict[str, Tuple[Path, str]] = {
        "claude": (
            home / ".claude" / "CLAUDE.md",
            (
                "# PAOS 跨端共享大脑挂载 (自动同步，勿手改块内内容)\n"
                "@~/.paos/brain/CORE_RULES.md\n"
                "@~/.paos/brain/USER.md\n"
                "@~/.paos/brain/memory/MEMORY.md\n"
                f"- 当前全局今日聚焦 (`~/.paos/brain/memory/TODAY.md`)：\n{summary['today_summary']}{hot_line}"
            ),
        ),
        "codex": (
            home / ".codex" / "AGENTS.md",
            (
                f"{summary['core_rules']}\n\n"
                "## PAOS 跨端共享状态指针\n"
                "- 季度边界：`~/.paos/brain/USER.md` | 长期记忆索引：`~/.paos/brain/memory/MEMORY.md` | 踩坑池：`~/.paos/brain/memory/learnings.md`\n"
                f"- 今日聚焦 (`TODAY.md`)：\n{summary['today_summary']}{hot_line}"
            ),
        ),
        "antigravity": (
            home / ".gemini" / "GEMINI.md",
            (
                f"{summary['core_rules']}\n\n"
                "## PAOS 跨端共享记忆总线指针\n"
                "- 季度边界：`~/.paos/brain/USER.md` | 共享记忆索引：`~/.paos/brain/memory/MEMORY.md` | 待分诊收件箱：`~/.paos/brain/memory/INBOX.md` | 踩坑池：`~/.paos/brain/memory/learnings.md`\n"
                f"- 今日全局 P0 (`~/.paos/brain/memory/TODAY.md`)：\n{summary['today_summary']}{hot_line}"
            ),
        ),
    }

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_root = home / ".paos" / "backups" / f"sync-{ts}"
    file_results: List[Dict[str, Any]] = []

    for hid in chosen:
        if hid == "cursor":
            mdc_path = home / ".cursor" / "rules" / "paos-shared.mdc"
            old_txt = mdc_path.read_text(encoding="utf-8") if mdc_path.is_file() else ""
            if remove:
                new_txt = ""
            else:
                new_txt = (
                    "---\n"
                    "description: PAOS Cross-Harness Shared Core Rules & Memory Pointers\n"
                    "alwaysApply: true\n"
                    "---\n\n"
                    f"{summary['core_rules']}\n\n"
                    f"Shared Memory Index: `~/.paos/brain/memory/MEMORY.md` | Learnings: `~/.paos/brain/memory/learnings.md`\n"
                )
            diff = "".join(
                difflib.unified_diff(
                    old_txt.splitlines(keepends=True),
                    new_txt.splitlines(keepends=True),
                    fromfile=str(mdc_path) + " (before)",
                    tofile=str(mdc_path) + " (after)",
                )
            )
            changed = old_txt != new_txt
            if changed and not dry_run:
                if remove and mdc_path.is_file():
                    mdc_path.unlink()
                elif not remove:
                    mdc_path.parent.mkdir(parents=True, exist_ok=True)
                    mdc_path.write_text(new_txt, encoding="utf-8")
            file_results.append({"target": "cursor", "path": str(mdc_path), "changed": changed, "diff": diff})
            continue

        dst_path, inner = compiled_blocks[hid]
        if remove and not dst_path.is_file():
            file_results.append({"target": hid, "path": str(dst_path), "changed": False, "diff": ""})
            continue

        old_txt = dst_path.read_text(encoding="utf-8") if dst_path.is_file() else ""
        new_txt = _upsert_managed_block(old_txt, inner, remove=remove)
        diff = "".join(
            difflib.unified_diff(
                old_txt.splitlines(keepends=True),
                new_txt.splitlines(keepends=True),
                fromfile=str(dst_path) + " (before)",
                tofile=str(dst_path) + " (after)",
            )
        )
        changed = old_txt != new_txt
        if changed and not dry_run:
            if dst_path.is_file() and BEGIN_MARKER not in old_txt:
                backup_root.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dst_path, backup_root / f"{hid}-{dst_path.name}.bak")
            if remove and not new_txt and dst_path.is_file():
                dst_path.unlink()
            else:
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                dst_path.write_text(new_txt, encoding="utf-8")
        file_results.append({"target": hid, "path": str(dst_path), "changed": changed, "diff": diff})

    return {
        "dry_run": dry_run,
        "remove": remove,
        "brain_dir": str(broot),
        "targets": chosen,
        "files": file_results,
    }


def promote_learnings(
    learnings_path: Path,
    threshold: int = 2,
    mark_promoted: bool = False,
) -> Dict[str, Any]:
    """Deterministically group repeated `[tag:...]` pitfalls ready for rule/hook promotion."""
    if not learnings_path.is_file():
        return {"path": str(learnings_path), "candidates": [], "marked_count": 0}

    lines = learnings_path.read_text(encoding="utf-8").splitlines()
    by_tag: Dict[str, List[Tuple[int, str]]] = {}
    for idx, line in enumerate(lines):
        if PROMOTED_RE.search(line):
            continue
        for tag in dict.fromkeys(TAG_RE.findall(line)).keys():
            by_tag.setdefault(tag, []).append((idx, line.strip()))

    candidates: List[Dict[str, Any]] = []
    to_mark_indices: set[int] = set()
    for tag, entries in sorted(by_tag.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if len(entries) >= threshold:
            candidates.append(
                {
                    "tag": tag,
                    "count": len(entries),
                    "entries": [txt for _, txt in entries],
                }
            )
            for line_idx, _ in entries:
                to_mark_indices.add(line_idx)

    if mark_promoted and to_mark_indices:
        stamp = datetime.now().strftime("%Y-%m-%d")
        new_lines = [
            (f"{l} [promoted:{stamp}]" if i in to_mark_indices else l)
            for i, l in enumerate(lines)
        ]
        learnings_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    return {
        "path": str(learnings_path),
        "threshold": threshold,
        "candidates": candidates,
        "marked_count": len(to_mark_indices) if mark_promoted else 0,
    }
