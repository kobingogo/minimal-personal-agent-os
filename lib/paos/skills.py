"""Skill graveyard (`skills-off/`) & profile switcher for controlling upfront context tax."""

from __future__ import annotations

from datetime import datetime
import fnmatch
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Tuple

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.S)


def _parse_skill_meta(skill_entry: Path) -> Dict[str, Any]:
    is_link = skill_entry.is_symlink()
    broken = is_link and not skill_entry.exists()
    target = os.readlink(skill_entry) if is_link else None

    desc = ""
    has_skill_md = False
    if not broken:
        md_path = skill_entry / "SKILL.md" if skill_entry.is_dir() else (
            skill_entry if skill_entry.suffix.lower() == ".md" else None
        )
        if md_path and md_path.is_file():
            has_skill_md = True
            txt = md_path.read_text(encoding="utf-8", errors="replace")
            m = FRONTMATTER_RE.match(txt)
            if m:
                for line in m.group(1).splitlines():
                    if line.strip().startswith("description:"):
                        desc = line.split(":", 1)[1].strip().strip("'\">-")
                        break
            if not desc:
                desc = txt[:160].strip()

    # Discovery overhead heuristic: name + description + XML/list wrapper (~45 tokens floor)
    est_tokens = 0 if broken else max(35, int((len(skill_entry.name) + len(desc)) / 3.2) + 18)
    return {
        "name": skill_entry.name,
        "is_symlink": is_link,
        "broken": broken,
        "target": target,
        "has_skill_md": has_skill_md,
        "est_discovery_tokens": est_tokens,
    }


def list_skills(home_dir: Path | None = None) -> Dict[str, Any]:
    home = home_dir or Path.home()
    active_dir = home / ".claude" / "skills"
    off_dir = home / ".claude" / "skills-off"

    active: List[Dict[str, Any]] = []
    parked: List[Dict[str, Any]] = []

    if active_dir.is_dir():
        for name in sorted(os.listdir(active_dir)):
            if name.startswith("."):
                continue
            active.append(_parse_skill_meta(active_dir / name))

    if off_dir.is_dir():
        for name in sorted(os.listdir(off_dir)):
            if name.startswith(".") or name.startswith("_"):
                continue
            parked.append(_parse_skill_meta(off_dir / name))

    est_total = sum(s["est_discovery_tokens"] for s in active)
    broken_count = sum(1 for s in active if s["broken"])
    return {
        "active_dir": str(active_dir),
        "off_dir": str(off_dir),
        "active_count": len(active),
        "parked_count": len(parked),
        "broken_active_count": broken_count,
        "estimated_active_tokens": est_total,
        "active": active,
        "parked": parked,
    }


def _update_manifest(off_dir: Path, action: str, names: List[str]) -> None:
    manifest_path = off_dir / "_paos_manifest.json"
    data: Dict[str, Any] = {"history": []}
    if manifest_path.is_file():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            data = {"history": []}
    data.setdefault("history", []).append(
        {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "action": action,
            "skills": names,
        }
    )
    data["history"] = data["history"][-100:]
    manifest_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def park_skills(names: List[str], home_dir: Path | None = None) -> Tuple[List[str], List[str]]:
    home = home_dir or Path.home()
    active_dir = home / ".claude" / "skills"
    off_dir = home / ".claude" / "skills-off"
    off_dir.mkdir(parents=True, exist_ok=True)

    moved: List[str] = []
    missing: List[str] = []
    for name in names:
        src = active_dir / name
        if not (src.exists() or src.is_symlink()):
            missing.append(name)
            continue
        dst = off_dir / name
        if dst.exists() or dst.is_symlink():
            if dst.is_symlink() or dst.is_file():
                dst.unlink()
            else:
                shutil.rmtree(dst)
        shutil.move(str(src), str(dst))
        moved.append(name)

    if moved:
        _update_manifest(off_dir, "park", moved)
    return (moved, missing)


def enable_skills(names: List[str], home_dir: Path | None = None) -> Tuple[List[str], List[str]]:
    home = home_dir or Path.home()
    active_dir = home / ".claude" / "skills"
    off_dir = home / ".claude" / "skills-off"
    active_dir.mkdir(parents=True, exist_ok=True)

    restored: List[str] = []
    missing: List[str] = []
    for name in names:
        src = off_dir / name
        if not (src.exists() or src.is_symlink()):
            missing.append(name)
            continue
        dst = active_dir / name
        if dst.exists() or dst.is_symlink():
            if dst.is_symlink() or dst.is_file():
                dst.unlink()
            else:
                shutil.rmtree(dst)
        shutil.move(str(src), str(dst))
        restored.append(name)

    if restored:
        _update_manifest(off_dir, "enable", restored)
    return (restored, missing)


def clean_broken_skills(home_dir: Path | None = None) -> List[str]:
    info = list_skills(home_dir)
    broken_names = [s["name"] for s in info["active"] if s["broken"]]
    if broken_names:
        park_skills(broken_names, home_dir)
    return broken_names


def apply_profile(
    profile_name: str,
    profiles_file: Path,
    home_dir: Path | None = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    cfg = json.loads(profiles_file.read_text(encoding="utf-8"))
    profiles = cfg.get("profiles") or {}
    if profile_name not in profiles:
        raise KeyError(f"未找到预设 '{profile_name}'，可选：{', '.join(sorted(profiles.keys()))}")

    always_keep: List[str] = list(cfg.get("always_keep") or [])
    patterns: List[str] = always_keep + list(profiles[profile_name].get("keep") or [])

    info = list_skills(home_dir)
    all_known = {s["name"] for s in info["active"]} | {s["name"] for s in info["parked"]}
    desired = {
        name for name in all_known if any(fnmatch.fnmatch(name, pat) for pat in patterns)
    }

    current_active = {s["name"] for s in info["active"]}
    current_parked = {s["name"] for s in info["parked"]}

    to_park = sorted(current_active - desired)
    to_enable = sorted(current_parked & desired)

    if not dry_run:
        if to_park:
            park_skills(to_park, home_dir)
        if to_enable:
            enable_skills(to_enable, home_dir)

    return {
        "profile": profile_name,
        "dry_run": dry_run,
        "to_park": to_park,
        "to_enable": to_enable,
        "resulting_active": sorted((current_active - set(to_park)) | set(to_enable)),
    }
