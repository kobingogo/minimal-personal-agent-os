"""Cross-harness skill matrix, canonical 1-hop store (`adopt`), `nvm`-style `use`, and `clean`."""

from __future__ import annotations

from datetime import datetime
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .skills import _parse_skill_meta

HARNESS_ORDER: Tuple[str, ...] = ("claude", "codex", "agents", "antigravity", "cursor")

HARNESS_SPECS: Dict[str, Dict[str, Any]] = {
    "claude": {
        "label": "Claude Code",
        "root": ".claude",
        "skills": ".claude/skills",
        "off": ".claude/skills-off",
        "instructions": [".claude/CLAUDE.md"],
        "orphan_globs": [".claude/.claude.json.tmp*", ".claude/shell-snapshots/*.tmp*"],
    },
    "codex": {
        "label": "Codex CLI/App",
        "root": ".codex",
        "skills": ".codex/skills",
        "off": ".codex/skills-off",
        "instructions": [".codex/AGENTS.md", ".codex/RTK.md"],
        "orphan_globs": [".codex/..codex-global-state.json*.tmp-*"],
    },
    "agents": {
        "label": "Shared .agents",
        "root": ".agents",
        "skills": ".agents/skills",
        "off": ".agents/skills-off",
        "instructions": [],
        "orphan_globs": [],
    },
    "antigravity": {
        "label": "Antigravity",
        "root": ".gemini/antigravity-cli",
        "skills": ".gemini/antigravity-cli/skills",
        "off": ".gemini/antigravity-cli/skills-off",
        "instructions": [".gemini/GEMINI.md"],
        "orphan_globs": [],
    },
    "cursor": {
        "label": "Cursor",
        "root": ".cursor",
        "skills": ".cursor/skills",
        "off": ".cursor/skills-off",
        "instructions": [],
        "orphan_globs": [],
    },
}


def resolve_targets(targets_arg: Optional[str], home: Path, only_installed: bool = True) -> List[str]:
    if targets_arg:
        raw = [t.strip().lower() for t in targets_arg.split(",") if t.strip()]
        if "all" in raw:
            raw = list(HARNESS_ORDER)
        unknown = [t for t in raw if t not in HARNESS_SPECS]
        if unknown:
            raise ValueError(f"未知客户端标识: {', '.join(unknown)}（可选: {', '.join(HARNESS_ORDER)}）")
        return raw

    if not only_installed:
        return list(HARNESS_ORDER)

    installed: List[str] = []
    for hid in HARNESS_ORDER:
        spec = HARNESS_SPECS[hid]
        if (home / spec["root"]).exists() or (home / spec["skills"]).exists():
            installed.append(hid)
    return installed


def _is_harness_skills_subpath(raw_target_abs: Path, home: Path) -> Optional[str]:
    """Return harness id if `raw_target_abs` points inside `<harness>/skills/<name>`."""
    for hid, spec in HARNESS_SPECS.items():
        sk_dir = home / spec["skills"]
        try:
            raw_target_abs.relative_to(sk_dir)
            return hid
        except ValueError:
            continue
    return None


def _find_heal_candidate(skill_name: str, home: Path) -> Optional[Path]:
    """Locate an intact directory for `skill_name` across PAOS store, `skills/`, or `skills-off/`."""
    store_candidate = home / ".paos" / "store" / "skills" / skill_name
    if store_candidate.exists():
        return store_candidate.resolve()

    for hid in HARNESS_ORDER:
        spec = HARNESS_SPECS[hid]
        for sub in (spec["skills"], spec["off"]):
            cand = home / sub / skill_name
            if cand.exists():
                return cand.resolve()
    return None


def _skill_md_hash(skill_dir: Path) -> Optional[str]:
    md = skill_dir / "SKILL.md"
    if not md.is_file():
        return None
    return hashlib.sha256(md.read_bytes()).hexdigest()[:16]


def _inside_external_git_repo(phys_dir: Path, home: Path) -> bool:
    """True if `phys_dir` lives outside harness dot-dirs (e.g. `~/workspace/skills/...`)."""
    managed_roots = [home / ".paos"] + [home / spec["root"] for spec in HARNESS_SPECS.values()]
    for mr in managed_roots:
        try:
            phys_dir.relative_to(mr)
            return False
        except ValueError:
            continue
    return True


def scan_matrix(home_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Scan all 5 harness slots for skill tax, daisy-chain symlinks, diverged copies & orphan bloat."""
    home = (home_dir or Path.home()).resolve()
    store_dir = home / ".paos" / "store" / "skills"
    store_count = (
        sum(1 for x in os.listdir(store_dir) if not x.startswith("."))
        if store_dir.is_dir()
        else 0
    )

    harnesses_report: List[Dict[str, Any]] = []
    physical_locations: Dict[str, List[Tuple[str, Path, Optional[str]]]] = {}
    unique_known_skills: Set[str] = set()
    total_active_tokens = 0
    total_broken = 0
    total_daisy = 0
    total_orphan_files = 0
    total_orphan_bytes = 0

    for hid in HARNESS_ORDER:
        spec = HARNESS_SPECS[hid]
        root_dir = home / spec["root"]
        sk_dir = home / spec["skills"]
        off_dir = home / spec["off"]
        installed = root_dir.exists() or sk_dir.exists()

        active_entries: List[Dict[str, Any]] = []
        broken_names: List[str] = []
        recoverable_broken: List[str] = []
        daisy_chain_names: List[str] = []
        ds_store_count = 0

        if sk_dir.is_dir():
            for name in sorted(os.listdir(sk_dir)):
                if name == ".DS_Store":
                    ds_store_count += 1
                    continue
                if name.startswith("."):
                    continue
                entry = sk_dir / name
                meta = _parse_skill_meta(entry)
                unique_known_skills.add(name)

                if entry.is_symlink():
                    raw_link = os.readlink(entry)
                    raw_abs = (
                        Path(raw_link)
                        if os.path.isabs(raw_link)
                        else Path(os.path.normpath(str(sk_dir / raw_link)))
                    )
                    if raw_abs.parent.exists():
                        raw_abs = raw_abs.parent.resolve() / raw_abs.name
                    upstream_h = _is_harness_skills_subpath(raw_abs, home)
                    if upstream_h and upstream_h != hid:
                        daisy_chain_names.append(name)
                        meta["daisy_chain_to"] = upstream_h

                    if meta["broken"]:
                        broken_names.append(name)
                        if _find_heal_candidate(name, home) is not None:
                            recoverable_broken.append(name)
                else:
                    if entry.is_dir():
                        physical_locations.setdefault(name, []).append(
                            (f"{hid}:active", entry, _skill_md_hash(entry))
                        )

                active_entries.append(meta)

        parked_count = 0
        if off_dir.is_dir():
            for name in sorted(os.listdir(off_dir)):
                if name.startswith(".") or name.startswith("_"):
                    continue
                parked_count += 1
                unique_known_skills.add(name)
                entry = off_dir / name
                if not entry.is_symlink() and entry.is_dir():
                    physical_locations.setdefault(name, []).append(
                        (f"{hid}:off", entry, _skill_md_hash(entry))
                    )

        # Instruction files footprint
        instr_info: List[Dict[str, Any]] = []
        for rel_i in spec["instructions"]:
            ip = home / rel_i
            if ip.is_file():
                txt = ip.read_text(encoding="utf-8", errors="replace")
                instr_info.append(
                    {
                        "path": f"~/{rel_i}",
                        "bytes": ip.stat().st_size,
                        "lines": len(txt.splitlines()),
                    }
                )

        # Orphan temp files
        orphan_files: List[str] = []
        orphan_bytes = 0
        for pat in spec["orphan_globs"]:
            for match in sorted(home.glob(pat)):
                if match.is_file() or match.is_symlink():
                    orphan_files.append(str(match.relative_to(home)))
                    try:
                        orphan_bytes += match.lstat().st_size
                    except OSError:
                        pass
        if ds_store_count:
            orphan_files.append(f"{spec['skills']}/.DS_Store")

        est_tok = sum(x["est_discovery_tokens"] for x in active_entries)
        total_active_tokens += est_tok
        total_broken += len(broken_names)
        total_daisy += len(daisy_chain_names)
        total_orphan_files += len(orphan_files)
        total_orphan_bytes += orphan_bytes

        harnesses_report.append(
            {
                "id": hid,
                "label": spec["label"],
                "installed": installed,
                "skills_dir": f"~/{spec['skills']}",
                "active_count": len(active_entries),
                "healthy_active_count": len(active_entries) - len(broken_names),
                "parked_count": parked_count,
                "broken_count": len(broken_names),
                "broken_names": broken_names,
                "recoverable_broken_names": recoverable_broken,
                "daisy_chain_count": len(daisy_chain_names),
                "daisy_chain_names": daisy_chain_names,
                "estimated_tokens": est_tok,
                "instructions": instr_info,
                "orphan_count": len(orphan_files),
                "orphan_bytes": orphan_bytes,
            }
        )

    # Identify duplicated physical directories across harnesses (potential drift forks)
    duplicates: List[Dict[str, Any]] = []
    for sname, locs in sorted(physical_locations.items()):
        if len(locs) >= 2:
            hashes = {h for _, _, h in locs if h is not None}
            duplicates.append(
                {
                    "skill": sname,
                    "copies": [tag for tag, _, _ in locs],
                    "diverged": len(hashes) > 1,
                }
            )

    state_file = home / ".paos" / "state.json"
    current_profile = None
    if state_file.is_file():
        try:
            current_profile = json.loads(state_file.read_text(encoding="utf-8")).get("active_profile")
        except Exception:
            current_profile = None

    return {
        "active_profile": current_profile,
        "store_dir": "~/.paos/store/skills",
        "store_skill_count": store_count,
        "unique_known_skills": len(unique_known_skills),
        "totals": {
            "estimated_tokens_across_harnesses": total_active_tokens,
            "broken_symlinks": total_broken,
            "daisy_chain_symlinks": total_daisy,
            "duplicate_physical_skills": len(duplicates),
            "diverged_physical_skills": sum(1 for d in duplicates if d["diverged"]),
            "orphan_temp_files": total_orphan_files,
            "orphan_temp_bytes": total_orphan_bytes,
        },
        "harnesses": harnesses_report,
        "duplicates": duplicates,
    }


def adopt_skills(
    home_dir: Optional[Path] = None,
    targets: Optional[Sequence[str]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Consolidate skills into `~/.paos/store/skills/` & rewire 1-hop symlinks (eliminates daisy-chains)."""
    home = (home_dir or Path.home()).resolve()
    target_ids = list(targets) if targets else resolve_targets(None, home, only_installed=True)
    store_dir = home / ".paos" / "store" / "skills"
    snap_dir = home / ".paos" / "snapshots"
    div_backup_root = home / ".paos" / "backups"

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    snapshot_entries: List[Dict[str, Any]] = []
    actions: List[str] = []
    adopted_skills: Set[str] = set()
    healed_links: List[str] = []
    backed_up_diverged: List[str] = []

    if not dry_run:
        store_dir.mkdir(parents=True, exist_ok=True)
        snap_dir.mkdir(parents=True, exist_ok=True)

    # Pass 1: Snapshot & populate canonical store `~/.paos/store/skills/<name>`
    for hid in target_ids:
        spec = HARNESS_SPECS[hid]
        for slot_kind, rel_dir in (("active", spec["skills"]), ("off", spec["off"])):
            base = home / rel_dir
            if not base.is_dir():
                continue
            for name in sorted(os.listdir(base)):
                if name.startswith(".") or name.startswith("_"):
                    continue
                entry = base / name
                is_link = entry.is_symlink()
                snapshot_entries.append(
                    {
                        "harness": hid,
                        "slot": slot_kind,
                        "path": str(entry),
                        "is_symlink": is_link,
                        "link_target": os.readlink(entry) if is_link else None,
                    }
                )

                canonical = store_dir / name
                if is_link:
                    if entry.exists():
                        real_target = entry.resolve()
                        if _inside_external_git_repo(real_target, home):
                            if not (canonical.exists() or canonical.is_symlink()):
                                actions.append(f"store link {name} -> {real_target}")
                                adopted_skills.add(name)
                                if not dry_run:
                                    os.symlink(str(real_target), str(canonical))
                        elif real_target != canonical and not (canonical.exists() or canonical.is_symlink()):
                            actions.append(f"move resolved {real_target} -> {canonical}")
                            adopted_skills.add(name)
                            if not dry_run:
                                shutil.move(str(real_target), str(canonical))
                elif entry.is_dir():
                    if not (canonical.exists() or canonical.is_symlink()):
                        actions.append(f"adopt dir {entry} -> {canonical}")
                        adopted_skills.add(name)
                        if not dry_run:
                            shutil.move(str(entry), str(canonical))
                            os.symlink(str(canonical), str(entry))
                    else:
                        # Canonical already exists: preserve any diverged copy before rewiring!
                        canon_real = canonical.resolve() if canonical.exists() else canonical
                        if entry.resolve() != canon_real:
                            h_canon = _skill_md_hash(canon_real)
                            h_entry = _skill_md_hash(entry)
                            if h_canon != h_entry:
                                b_dst = div_backup_root / f"diverged-{ts}" / hid / name
                                backed_up_diverged.append(f"{hid}:{name}")
                                actions.append(f"backup diverged {entry} -> {b_dst}")
                                if not dry_run:
                                    b_dst.parent.mkdir(parents=True, exist_ok=True)
                                    shutil.move(str(entry), str(b_dst))
                                    os.symlink(str(canonical), str(entry))
                            else:
                                actions.append(f"dedup identical dir {entry} -> symlink {canonical}")
                                if not dry_run:
                                    shutil.rmtree(entry)
                                    os.symlink(str(canonical), str(entry))

    # Pass 2: Rewire all active/off symlinks into direct 1-hop symlinks to `~/.paos/store/skills/<name>`
    # AND heal broken daisy-chain symlinks whose skill now lives in store!
    for hid in target_ids:
        spec = HARNESS_SPECS[hid]
        for slot_kind, rel_dir in (("active", spec["skills"]), ("off", spec["off"])):
            base = home / rel_dir
            if not base.is_dir():
                continue
            for name in sorted(os.listdir(base)):
                if name.startswith(".") or name.startswith("_"):
                    continue
                entry = base / name
                canonical = store_dir / name
                store_has = canonical.exists() or canonical.is_symlink() or (name in adopted_skills)
                if not store_has:
                    # Check if another non-targeted harness has it
                    cand = _find_heal_candidate(name, home)
                    if cand is not None and _inside_external_git_repo(cand, home):
                        store_has = True
                        if not dry_run and not (canonical.exists() or canonical.is_symlink()):
                            os.symlink(str(cand), str(canonical))

                if not store_has:
                    continue

                if entry.is_symlink():
                    was_broken = not entry.exists()
                    cur_link = os.readlink(entry)
                    if cur_link != str(canonical):
                        if was_broken:
                            healed_links.append(f"{hid}:{name}")
                            actions.append(f"heal broken link {entry} -> {canonical}")
                        else:
                            actions.append(f"rewire 1-hop {entry} -> {canonical}")
                        if not dry_run:
                            entry.unlink()
                            os.symlink(str(canonical), str(entry))

    snapshot_path: Optional[str] = None
    if not dry_run and snapshot_entries:
        sp = snap_dir / f"links-{ts}.json"
        sp.write_text(
            json.dumps({"timestamp": ts, "targets": target_ids, "entries": snapshot_entries}, ensure_ascii=False, indent=2)
            + "\n",
            encoding="utf-8",
        )
        snapshot_path = str(sp)

    return {
        "dry_run": dry_run,
        "targets": target_ids,
        "store_dir": str(store_dir),
        "adopted_count": len(adopted_skills),
        "healed_broken_links": healed_links,
        "backed_up_diverged": backed_up_diverged,
        "action_count": len(actions),
        "actions": actions,
        "snapshot_path": snapshot_path,
    }


def restore_links(home_dir: Optional[Path] = None) -> Tuple[bool, str]:
    """Restore symlink topology from the latest `~/.paos/snapshots/links-*.json` snapshot."""
    home = (home_dir or Path.home()).resolve()
    snap_dir = home / ".paos" / "snapshots"
    if not snap_dir.is_dir():
        return (False, "未找到快照目录 ~/.paos/snapshots/。")
    snaps = sorted(snap_dir.glob("links-*.json"))
    if not snaps:
        return (False, "未找到任何可回滚的链接拓扑快照。")

    latest = snaps[-1]
    data = json.loads(latest.read_text(encoding="utf-8"))
    store_dir = home / ".paos" / "store" / "skills"

    restored = 0
    for item in data.get("entries") or []:
        p = Path(item["path"])
        p.parent.mkdir(parents=True, exist_ok=True)
        if item["is_symlink"] and item["link_target"]:
            if p.is_symlink() or p.is_file():
                p.unlink()
            elif p.is_dir():
                shutil.rmtree(p)
            os.symlink(item["link_target"], str(p))
            restored += 1
        elif not item["is_symlink"]:
            # If entry was originally a physical dir and is now a symlink to store, copy back
            if p.is_symlink():
                name = p.name
                canon = store_dir / name
                p.unlink()
                if canon.is_dir() and not canon.is_symlink():
                    shutil.copytree(canon, p)
                    restored += 1

    return (True, f"已从快照 {latest} 恢复 {restored} 项链接拓扑。")


def _discover_skill_pool(home: Path, target_ids: Sequence[str]) -> Dict[str, Path]:
    """Map every known intact skill `name` -> best source path (preferring `~/.paos/store/skills`)."""
    pool: Dict[str, Path] = {}
    store_dir = home / ".paos" / "store" / "skills"
    if store_dir.is_dir():
        for name in sorted(os.listdir(store_dir)):
            if name.startswith("."):
                continue
            cand = store_dir / name
            if cand.exists():
                pool[name] = cand

    scan_ids = list(dict.fromkeys(list(target_ids) + list(HARNESS_ORDER)))
    for hid in scan_ids:
        spec = HARNESS_SPECS[hid]
        for sub in (spec["skills"], spec["off"]):
            d = home / sub
            if not d.is_dir():
                continue
            for name in sorted(os.listdir(d)):
                if name.startswith(".") or name.startswith("_") or name in pool:
                    continue
                cand = d / name
                if cand.exists():
                    pool[name] = cand.resolve()
    return pool


def use_profile(
    profile_name: str,
    profiles_file: Path,
    home_dir: Optional[Path] = None,
    targets: Optional[Sequence[str]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """`nvm use` for AI Agent skills: switch active skills across all targeted harnesses in <50ms."""
    home = (home_dir or Path.home()).resolve()
    cfg = json.loads(profiles_file.read_text(encoding="utf-8"))
    profiles = cfg.get("profiles") or {}
    if profile_name not in profiles:
        raise KeyError(f"未找到预设 '{profile_name}'，可选：{', '.join(sorted(profiles.keys()))}")

    target_ids = list(targets) if targets else resolve_targets(None, home, only_installed=True)
    always_keep: List[str] = list(cfg.get("always_keep") or [])
    patterns: List[str] = always_keep + list(profiles[profile_name].get("keep") or [])

    pool = _discover_skill_pool(home, target_ids)
    desired_names = {
        name for name in pool.keys() if any(fnmatch.fnmatch(name, pat) for pat in patterns)
    }

    store_dir = home / ".paos" / "store" / "skills"
    per_harness: List[Dict[str, Any]] = []

    for hid in target_ids:
        spec = HARNESS_SPECS[hid]
        sk_dir = home / spec["skills"]
        off_dir = home / spec["off"]

        before_tokens = 0
        current_active: Set[str] = set()
        broken_parked: List[str] = []

        if sk_dir.is_dir():
            for name in sorted(os.listdir(sk_dir)):
                if name.startswith("."):
                    continue
                meta = _parse_skill_meta(sk_dir / name)
                before_tokens += meta["est_discovery_tokens"]
                if meta["broken"] and name not in desired_names:
                    broken_parked.append(name)
                current_active.add(name)

        to_park = sorted(current_active - desired_names)
        to_enable = sorted(desired_names - (current_active - set(broken_parked)))
        # Also re-link any desired skill whose current link in `sk_dir` is broken!
        if sk_dir.is_dir():
            for name in sorted(current_active & desired_names):
                if (sk_dir / name).is_symlink() and not (sk_dir / name).exists() and name in pool:
                    if name not in to_enable:
                        to_enable.append(name)

        if not dry_run:
            sk_dir.mkdir(parents=True, exist_ok=True)
            off_dir.mkdir(parents=True, exist_ok=True)

            # 1. Park undesired entries safely
            for name in to_park:
                src = sk_dir / name
                if not (src.exists() or src.is_symlink()):
                    continue
                # If already backed by `~/.paos/store/skills/<name>`, move symlink into `skills-off/`
                dst = off_dir / name
                if dst.exists() or dst.is_symlink():
                    if dst.is_symlink() or dst.is_file():
                        dst.unlink()
                    else:
                        shutil.rmtree(dst)
                shutil.move(str(src), str(dst))

            # 2. Enable desired entries (preferring direct 1-hop symlink to store or canonical source)
            for name in to_enable:
                dst = sk_dir / name
                if dst.is_symlink() and not dst.exists():
                    dst.unlink()
                if dst.exists():
                    continue
                off_cand = off_dir / name
                store_cand = store_dir / name
                if store_cand.exists() or store_cand.is_symlink():
                    if off_cand.is_symlink():
                        off_cand.unlink()
                    os.symlink(str(store_cand), str(dst))
                elif off_cand.exists():
                    shutil.move(str(off_cand), str(dst))
                elif name in pool:
                    os.symlink(str(pool[name]), str(dst))

        after_tokens = 0
        after_active_count = 0
        if not dry_run and sk_dir.is_dir():
            for name in sorted(os.listdir(sk_dir)):
                if name.startswith("."):
                    continue
                m = _parse_skill_meta(sk_dir / name)
                after_tokens += m["est_discovery_tokens"]
                after_active_count += 1
        else:
            # Estimate dry-run tokens from pool
            for name in sorted(desired_names):
                m = _parse_skill_meta(pool[name])
                after_tokens += m["est_discovery_tokens"]
            after_active_count = len(desired_names)

        per_harness.append(
            {
                "harness": hid,
                "label": spec["label"],
                "before_active": len(current_active),
                "after_active": after_active_count,
                "before_tokens": before_tokens,
                "after_tokens": after_tokens,
                "delta_tokens": after_tokens - before_tokens,
                "parked_count": len(to_park),
                "enabled_count": len(to_enable),
                "to_park": to_park,
                "to_enable": to_enable,
            }
        )

    if not dry_run:
        paos_dir = home / ".paos"
        paos_dir.mkdir(parents=True, exist_ok=True)
        (paos_dir / "state.json").write_text(
            json.dumps(
                {
                    "active_profile": profile_name,
                    "updated_at": datetime.now().isoformat(timespec="seconds"),
                    "targets": target_ids,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    return {
        "profile": profile_name,
        "description": profiles[profile_name].get("description", ""),
        "dry_run": dry_run,
        "targets": target_ids,
        "desired_skill_count": len(desired_names),
        "desired_skills": sorted(desired_names),
        "harnesses": per_harness,
    }


def clean_harnesses(
    home_dir: Optional[Path] = None,
    targets: Optional[Sequence[str]] = None,
    heal_links: bool = True,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Safely clean orphan `.tmp-*` crash files, `.DS_Store`, and heal/quarantine broken symlinks."""
    home = (home_dir or Path.home()).resolve()
    target_ids = list(targets) if targets else resolve_targets(None, home, only_installed=True)

    removed_orphans: List[str] = []
    reclaimed_bytes = 0
    healed_symlinks: List[str] = []
    quarantined_symlinks: List[str] = []

    for hid in target_ids:
        spec = HARNESS_SPECS[hid]
        sk_dir = home / spec["skills"]
        off_dir = home / spec["off"]

        # 1. Orphan crash/temp files
        for pat in spec["orphan_globs"]:
            for match in sorted(home.glob(pat)):
                if match.is_file() or match.is_symlink():
                    try:
                        sz = match.lstat().st_size
                    except OSError:
                        sz = 0
                    removed_orphans.append(str(match.relative_to(home)))
                    reclaimed_bytes += sz
                    if not dry_run:
                        match.unlink()

        # 2. `.DS_Store` & broken symlinks in `<harness>/skills`
        if sk_dir.is_dir():
            for name in sorted(os.listdir(sk_dir)):
                entry = sk_dir / name
                if name == ".DS_Store" and entry.is_file():
                    try:
                        reclaimed_bytes += entry.stat().st_size
                    except OSError:
                        pass
                    removed_orphans.append(str(entry.relative_to(home)))
                    if not dry_run:
                        entry.unlink()
                    continue

                if name.startswith("."):
                    continue

                if entry.is_symlink() and not entry.exists():
                    cand = _find_heal_candidate(name, home) if heal_links else None
                    if cand is not None:
                        healed_symlinks.append(f"{hid}:{name} -> {cand}")
                        if not dry_run:
                            entry.unlink()
                            os.symlink(str(cand), str(entry))
                    else:
                        quarantined_symlinks.append(f"{hid}:{name}")
                        if not dry_run:
                            q_dir = off_dir / "_broken"
                            q_dir.mkdir(parents=True, exist_ok=True)
                            q_dst = q_dir / name
                            if q_dst.exists() or q_dst.is_symlink():
                                q_dst.unlink()
                            shutil.move(str(entry), str(q_dst))

    return {
        "dry_run": dry_run,
        "targets": target_ids,
        "removed_orphan_files": removed_orphans,
        "reclaimed_bytes": reclaimed_bytes,
        "healed_symlinks": healed_symlinks,
        "quarantined_broken_symlinks": quarantined_symlinks,
    }
