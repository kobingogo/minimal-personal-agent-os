"""Unified Cross-Harness Memory & Rule Compiler (`~/.paos/brain/` -> Claude/Codex/Antigravity/Cursor).

Uses non-destructive `<!-- PAOS:BEGIN --> ... <!-- PAOS:END -->` managed blocks so user-authored
instructions are preserved 100% intact, with automatic first-touch backups.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import difflib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .audit import paos_home

BEGIN_MARKER = "<!-- PAOS:BEGIN -->"
END_MARKER = "<!-- PAOS:END -->"
MANAGED_BLOCK_RE = re.compile(
    re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER) + r"\n?",
    re.S,
)
# Supports ASCII slugs and CJK/Unicode tags like `[tag:cache-bust]` or `[tag:缓存穿透]`
TAG_RE = re.compile(r"\[tag:([^\s\[\]]+)\]")
PROMOTED_RE = re.compile(r"\[promoted:")
POLICY_LINE_RE = re.compile(
    r"(^#{1,3}\s+|\b(?:must|never|do not|forbidden|security|secret|redline)\b|禁止|严禁|红线|铁律|必须)",
    re.I,
)
ALLOWED_SYNC_TARGETS = ("claude", "codex", "antigravity", "cursor")
MAX_CORE_RULES_CHARS = 4000

DEFAULT_CORE_RULES = """# PAOS 跨端共享核心工程契约 (CORE_RULES)
- 结论先行，简洁直接；执行删除、覆盖或外发操作前先说明影响并等待确认。
- 一模型一坑：先给 3 行可检验验收标准再动手；同一报错连续修 2 次未过立即停机换思路。
- 严守上下文信噪比：长期记忆索引死守 <=200 行指针，新踩坑先记入 `learnings.md` 草稿池。
"""

DEFAULT_SHARED_USER = """# 个人季度主线与边界 (USER)
- 主线 1：聚焦核心产品与自动化工程交付，砍掉偏离主线的低优需求。
- 主线 2：沉淀高复用确定性脚本与工程护栏（钩子与单测优先于纯文字叮嘱）。
- 禁区边界：个人财务、主账号根私钥与未脱敏生产凭证严禁混入编码工作区。
"""

DEFAULT_HEARTBEAT = """# HEARTBEAT.md（每日晨间只读巡检清单）
- 检查 `~/.paos/brain/memory/INBOX.md` 与 `learnings.md` 中积压的未处理事项。
- 提炼最多 3 条今日最值得优先收敛的技术债、复发坑点或待分诊事项（每行必须以 `- ` 开头）。
- 严禁修改任何代码、规则或配置文件。
"""


def brain_root(home_dir: Optional[Path] = None) -> Path:
    return paos_home(home_dir) / ".paos" / "brain"


def scan_unpromoted_tags(learnings_path: Path) -> Counter[str]:
    """Count recurring `[tag:...]` occurrences across unpromoted lines (deduplicated per line)."""
    counts: Counter[str] = Counter()
    if not learnings_path.is_file():
        return counts
    try:
        lines = learnings_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return counts
    for line in lines:
        if not PROMOTED_RE.search(line):
            counts.update(dict.fromkeys(TAG_RE.findall(line)).keys())
    return counts


def init_brain(
    home_dir: Optional[Path] = None,
    seed_workspace: Optional[Path] = None,
    repo_profiles_template: Optional[Path] = None,
) -> Dict[str, Any]:
    """Initialize `~/.paos/brain/` shared state & user `~/.paos/skill-profiles.json` idempotently."""
    home = paos_home(home_dir)
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

    _ensure_file(broot / "CORE_RULES.md", DEFAULT_CORE_RULES, "CORE_RULES.md")
    _ensure_file(broot / "USER.md", DEFAULT_SHARED_USER, "USER.md")
    _ensure_file(broot / "HEARTBEAT.md", DEFAULT_HEARTBEAT, "HEARTBEAT.md")
    _ensure_file(
        mem / "TODAY.md",
        "# 今日聚焦 (最多 3 件 P0)\n\n- [ ] 运行 `paos status` 查看五端状态与上下文税\n",
        "memory/TODAY.md",
    )
    _ensure_file(mem / "INBOX.md", "# 全局待分诊收件箱 (INBOX)\n\n", "memory/INBOX.md")
    _ensure_file(
        mem / "MEMORY.md",
        "# 跨客户端共享记忆总索引 (<=200 行硬上限)\n\n- 踩坑与防呆记录见 `~/.paos/brain/memory/learnings.md`\n",
        "memory/MEMORY.md",
    )
    _ensure_file(
        mem / "learnings.md",
        "# 待审校纠偏草稿箱 (Learnings)\n\n<!-- 格式: - [YYYY-MM-DD] [tag:slug] 现象 -> 根因 -> 防复发动作 -->\n",
        "memory/learnings.md",
    )

    user_profiles = home / ".paos" / "skill-profiles.json"
    if not user_profiles.is_file() and repo_profiles_template and repo_profiles_template.is_file():
        shutil.copy2(repo_profiles_template, user_profiles)
        created.append(str(user_profiles))

    return {"brain_dir": str(broot), "created_files": created}


def _compact_core_rules(core_txt: str, max_chars: int = MAX_CORE_RULES_CHARS) -> str:
    """Structure-preserving truncation: keep 45% head + Policy Digest red-lines + 15% tail."""
    if len(core_txt) <= max_chars:
        return core_txt
    head_budget = int(max_chars * 0.45)
    tail_budget = int(max_chars * 0.15)
    digest_budget = max(200, max_chars - head_budget - tail_budget - 80)
    head = core_txt[:head_budget].rstrip()
    tail = core_txt[-tail_budget:].lstrip()
    middle = core_txt[head_budget : len(core_txt) - tail_budget]
    digest_lines: List[str] = []
    used = 0
    for line in middle.splitlines():
        s = line.strip()
        if s and POLICY_LINE_RE.search(s):
            if used + len(s) + 1 > digest_budget:
                break
            digest_lines.append(s)
            used += len(s) + 1
    digest_block = (
        "\n[Policy Digest · 中段红线保底摘要]\n" + "\n".join(digest_lines)
        if digest_lines
        else "\n...[中段细则已折叠，详见 ~/.paos/brain/CORE_RULES.md]..."
    )
    return f"{head}\n{digest_block}\n{tail}"


def _check_anti_erosion(home: Path, broot: Path, allow_shrink: bool = False, dry_run: bool = False) -> None:
    """Guard against silent LLM memory/rule erosion (>50% sudden line drop on files with >=6 lines)."""
    if not broot.is_dir():
        return
    state_file = home / ".paos" / "state" / "brain-guard.json"
    prev: Dict[str, int] = {}
    if state_file.is_file():
        try:
            data = json.loads(state_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                prev = {k: int(v) for k, v in data.items() if isinstance(v, int)}
        except Exception:
            prev = {}

    curr: Dict[str, int] = {}
    for rel in ("CORE_RULES.md", "memory/MEMORY.md"):
        fp = broot / rel
        if fp.is_file():
            curr[rel] = sum(1 for l in fp.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip())

    if not allow_shrink:
        for rel, new_cnt in curr.items():
            old_cnt = prev.get(rel, 0)
            if old_cnt >= 6 and new_cnt < (old_cnt / 2.0):
                raise RuntimeError(
                    f"防侵蚀熔断 (ESUSPECT_SHRINK)：`{rel}` 非空行数从 {old_cnt} 行骤降至 {new_cnt} 行（>50% 丢失）。"
                    "请检查是否被模型误覆盖；若确属人工精简，请加 `--allow-shrink` 重跑 `paos sync`。"
                )

    if not dry_run and curr:
        try:
            state_file.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            merged = {**prev, **curr}
            state_file.write_text(json.dumps(merged, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass


def _extract_active_summary(broot: Path) -> Dict[str, str]:
    raw_core = (broot / "CORE_RULES.md").read_text(encoding="utf-8").strip() if (broot / "CORE_RULES.md").is_file() else ""
    core_txt = _compact_core_rules(raw_core)
    today_p = broot / "memory" / "TODAY.md"
    today_lines: List[str] = []
    if today_p.is_file():
        today_lines = [
            l.strip()
            for l in today_p.read_text(encoding="utf-8").splitlines()
            if l.strip().startswith("- [ ]")
        ][:3]

    counts = scan_unpromoted_tags(broot / "memory" / "learnings.md")
    hot_tags = [f"{t}({c}次)" for t, c in counts.most_common(3) if c >= 2]

    return {
        "core_rules": core_txt,
        "today_summary": "\n".join(today_lines) if today_lines else "- (暂无未完成 P0，可通过 `paos capture` 或编辑 `~/.paos/brain/memory/TODAY.md` 设定)",
        "hot_tags": ", ".join(hot_tags),
    }


def _sanitize_block_inner(block_inner: str) -> str:
    """Prevent accidental marker strings inside user notes from breaking `MANAGED_BLOCK_RE`."""
    return block_inner.replace(BEGIN_MARKER, "<!-- PAOS_BEGIN -->").replace(END_MARKER, "<!-- PAOS_END -->")


def _upsert_managed_block(existing: str, block_inner: str, remove: bool = False) -> str:
    if remove:
        if BEGIN_MARKER not in existing:
            return existing
        cleaned = MANAGED_BLOCK_RE.sub("", existing).rstrip()
        return (cleaned + "\n") if cleaned else ""

    safe_inner = _sanitize_block_inner(block_inner).rstrip()
    wrapped = f"{BEGIN_MARKER}\n{safe_inner}\n{END_MARKER}\n"
    if MANAGED_BLOCK_RE.search(existing):
        return MANAGED_BLOCK_RE.sub(lambda _m: wrapped, existing, count=1)

    base = existing.rstrip()
    if not base:
        return wrapped
    return f"{base}\n\n{wrapped}"


def _write_preserving_symlink(dst_path: Path, content: str) -> None:
    target = dst_path.resolve() if dst_path.is_symlink() else dst_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def sync_brain(
    home_dir: Optional[Path] = None,
    targets: Optional[Sequence[str]] = None,
    dry_run: bool = False,
    remove: bool = False,
    allow_shrink: bool = False,
) -> Dict[str, Any]:
    """Compile `~/.paos/brain/` into Claude, Codex, Antigravity, and Cursor non-destructively."""
    home = paos_home(home_dir)
    broot = brain_root(home)
    if not remove and not broot.is_dir():
        if not dry_run:
            init_brain(home)
    if not remove:
        _check_anti_erosion(home, broot, allow_shrink=allow_shrink, dry_run=dry_run)

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
        "cursor": (
            home / ".cursor" / "rules" / "paos-shared.mdc",
            (
                f"{summary['core_rules']}\n\n"
                "## PAOS Shared Pointers\n"
                "- User Goals: `~/.paos/brain/USER.md` | Memory Index: `~/.paos/brain/memory/MEMORY.md` | Learnings: `~/.paos/brain/memory/learnings.md`\n"
                f"- Today Focus (`TODAY.md`):\n{summary['today_summary']}{hot_line}"
            ),
        ),
    }

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_root = home / ".paos" / "backups" / f"sync-{ts}"
    file_results: List[Dict[str, Any]] = []

    for hid in chosen:
        dst_path, inner = compiled_blocks[hid]
        if remove and not dst_path.is_file():
            file_results.append({"target": hid, "path": str(dst_path), "changed": False, "diff": ""})
            continue

        old_txt = dst_path.read_text(encoding="utf-8") if dst_path.is_file() else ""
        if hid == "cursor" and not old_txt and not remove:
            header = "---\ndescription: PAOS Cross-Harness Shared Core Rules & Memory Pointers\nalwaysApply: true\n---\n"
            new_txt = _upsert_managed_block(header, inner, remove=False)
        else:
            new_txt = _upsert_managed_block(old_txt, inner, remove=remove)
            if hid == "cursor" and remove and new_txt.strip() in (
                "---\ndescription: PAOS Cross-Harness Shared Core Rules & Memory Pointers\nalwaysApply: true\n---",
                "",
            ):
                new_txt = ""

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
                _write_preserving_symlink(dst_path, new_txt)
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
