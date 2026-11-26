"""Cross-harness skill matrix, canonical 1-hop store (`adopt`), `nvm`-style `use`, and `clean`."""

from __future__ import annotations

from datetime import datetime
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .audit import paos_home

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.S)
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
        "instructions": [".codex/AGENTS.md"],
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


def _validate_skill_name(name: str) -> str:
    """Reject empty names, `.`/`..`, and any path separator to prevent directory traversal/`rmtree` accidents."""
    s = name.strip()
    if not s or s in (".", "..") or "/" in s or "\\" in s:
        raise ValueError(f"非法技能名称: {name!r}（仅允许单层目录名，禁止包含 `.`、`..` 或路径分隔符）")
    return s


def _parse_skill_meta(skill_entry: Path) -> Dict[str, Any]:
    is_link = skill_entry.is_symlink()
    broken = is_link and not skill_entry.exists()
    target = os.readlink(skill_entry) if is_link else None

    desc = ""
    has_skill_md = False
    if not broken:
        md_path = (
            skill_entry / "SKILL.md"
            if skill_entry.is_dir()
            else (skill_entry if skill_entry.suffix.lower() == ".md" else None)
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

    est_tokens = 0 if broken else max(35, int((len(skill_entry.name) + len(desc)) / 3.2) + 18)
    return {
        "name": skill_entry.name,
        "is_symlink": is_link,
        "broken": broken,
        "target": target,
        "has_skill_md": has_skill_md,
        "est_discovery_tokens": est_tokens,
    }


def _is_harness_installed(hid: str, home: Path) -> bool:
    spec = HARNESS_SPECS[hid]
    if (home / spec["root"]).exists() or (home / spec["skills"]).exists():
        return True
    if hid == "antigravity" and (home / ".gemini").exists():
        return True
    return False


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

    return [hid for hid in HARNESS_ORDER if _is_harness_installed(hid, home)]


def _is_harness_skills_subpath(raw_target_abs: Path, home: Path) -> Optional[str]:
    for hid, spec in HARNESS_SPECS.items():
        sk_dir = home / spec["skills"]
        try:
            raw_target_abs.relative_to(sk_dir)
            return hid
        except ValueError:
            continue
    return None


def _find_heal_candidate(skill_name: str, home: Path) -> Optional[Path]:
    store_cand = home / ".paos" / "store" / "skills" / skill_name
    if store_cand.exists():
        return store_cand

    for hid in HARNESS_ORDER:
        spec = HARNESS_SPECS[hid]
        for sub in (spec["off"], spec["skills"]):
            cand = home / sub / skill_name
            if cand.exists():
                return cand.resolve()
    return None


def _skill_tree_hash(skill_dir: Path) -> Optional[str]:
    """Compute SHA-256 over the ENTIRE directory tree (relative paths, file bytes, symlink targets).

    Returns `None` if `skill_dir` is empty or unreadable so empty/unhashed dirs are NEVER treated as identical.
    """
    if not skill_dir.is_dir():
        return None
    hasher = hashlib.sha256()
    file_count = 0
    try:
        for root_str, dirnames, filenames in os.walk(skill_dir, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__" and d != ".DS_Store")
            rel_root = os.path.relpath(root_str, skill_dir)
            for fname in sorted(filenames):
                if fname == ".DS_Store":
                    continue
                fpath = Path(root_str) / fname
                rel_p = fname if rel_root == "." else f"{rel_root}/{fname}"
                hasher.update(rel_p.encode("utf-8", errors="surrogateescape") + b"\x00")
                if fpath.is_symlink():
                    hasher.update(b"L:" + os.readlink(fpath).encode("utf-8", errors="surrogateescape") + b"\x00")
                elif fpath.is_file():
                    hasher.update(b"F:")
                    hasher.update(fpath.read_bytes())
                    hasher.update(b"\x00")
                file_count += 1
    except OSError:
        return None
    return hasher.hexdigest()[:16] if file_count > 0 else None


def _inside_external_git_repo(real_path: Path, home: Path) -> bool:
    cur = real_path
    while cur != cur.parent and cur != home:
        if (cur / ".git").exists():
            return not any(
                str(cur).startswith(str(home / HARNESS_SPECS[h]["root"])) for h in HARNESS_ORDER
            )
        cur = cur.parent
    return False


def _backup_or_remove_dst(dst: Path, backup_dir: Path, tag: str) -> None:
    """Safely clear `dst`: symlinks/files are unlinked; real directories are backed up instead of `rmtree`!"""
    if not (dst.exists() or dst.is_symlink()):
        return
    if dst.is_symlink() or dst.is_file():
        dst.unlink()
    else:
        backup_dir.mkdir(parents=True, exist_ok=True)
        b_target = backup_dir / f"{tag}-{dst.name}"
        if b_target.exists():
            shutil.rmtree(b_target, ignore_errors=True)
        shutil.move(str(dst), str(b_target))


def scan_matrix(home_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Scan all 5 Agent harnesses in ~20ms (read-only)."""
    home = paos_home(home_dir)
    store_dir = home / ".paos" / "store" / "skills"
    store_count = (
        len([n for n in os.listdir(store_dir) if not n.startswith(".")])
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
        sk_dir = home / spec["skills"]
        off_dir = home / spec["off"]
        installed = _is_harness_installed(hid, home)

        active_entries: List[Dict[str, Any]] = []
        broken_names: List[str] = []
        recoverable_broken: List[str] = []
        daisy_chain_names: List[str] = []

        if sk_dir.is_dir():
            for name in sorted(os.listdir(sk_dir)):
                if name.startswith("."):
                    continue
                entry = sk_dir / name
                meta = _parse_skill_meta(entry)
                unique_known_skills.add(name)

                if entry.is_symlink():
                    raw_link = Path(os.readlink(entry))
                    raw_abs = raw_link if raw_link.is_absolute() else (sk_dir / raw_link)
                    norm_abs = raw_abs.parent.resolve() / raw_abs.name
                    via_harness = _is_harness_skills_subpath(norm_abs, home.resolve())
                    if via_harness and via_harness != hid:
                        daisy_chain_names.append(f"{name} -> {via_harness}")
                    if meta["broken"]:
                        broken_names.append(name)
                        if _find_heal_candidate(name, home) is not None:
                            recoverable_broken.append(name)
                elif entry.is_dir():
                    physical_locations.setdefault(name, []).append(
                        (f"{hid}:active", entry, _skill_tree_hash(entry))
                    )

                active_entries.append(meta)

        parked_count = 0
        if off_dir.is_dir():
            for name in sorted(os.listdir(off_dir)):
                if name.startswith(".") or name.startswith("_"):
                    continue
                parked_count += 1
                unique_known_skills.add(name)
                off_entry = off_dir / name
                if not off_entry.is_symlink() and off_entry.is_dir():
                    physical_locations.setdefault(name, []).append(
                        (f"{hid}:off", off_entry, _skill_tree_hash(off_entry))
                    )

        instr_info: List[Dict[str, Any]] = []
        for rel_i in spec["instructions"]:
            ip = home / rel_i
            if ip.is_file():
                sz = ip.stat().st_size
                instr_info.append({"path": f"~/{rel_i}", "bytes": sz, "est_tokens": int(sz / 3.5)})

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
        for ds_dir in (sk_dir, off_dir):
            ds = ds_dir / ".DS_Store"
            if ds.is_file():
                orphan_files.append(str(ds.relative_to(home)))
                orphan_bytes += ds.stat().st_size

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

    duplicates: List[Dict[str, Any]] = []
    for sname, locs in sorted(physical_locations.items()):
        if len(locs) >= 2:
            hashes = {h for _, _, h in locs if h is not None}
            has_none = any(h is None for _, _, h in locs)
            duplicates.append(
                {
                    "skill": sname,
                    "copies": [tag for tag, _, _ in locs],
                    "diverged": len(hashes) > 1 or has_none,
                }
            )

    state_file = home / ".paos" / "state.json"
    current_profile = None
    if state_file.is_file():
        try:
            current_profile = json.loads(state_file.read_text(encoding="utf-8")).get("active_profile")
        except Exception:
            current_profile = None

    agy_plugins = scan_agy_plugins(home)

    return {
        "active_profile": current_profile,
        "store_dir": "~/.paos/store/skills",
        "store_skill_count": store_count,
        "unique_known_skills": len(unique_known_skills),
        "totals": {
            "active_entries_across_harnesses": sum(h["active_count"] for h in harnesses_report),
            "estimated_tokens_across_harnesses": total_active_tokens,
            "estimated_agy_plugin_tokens": agy_plugins["enabled_tokens"],
            "broken_symlinks": total_broken,
            "daisy_chain_symlinks": total_daisy,
            "duplicate_physical_skills": len(duplicates),
            "diverged_physical_skills": sum(1 for d in duplicates if d["diverged"]),
            "orphan_temp_files": total_orphan_files,
            "orphan_temp_bytes": total_orphan_bytes,
        },
        "harnesses": harnesses_report,
        "agy_plugins": agy_plugins,
        "duplicates": duplicates,
    }


def scan_agy_plugins(home_dir: Optional[Path] = None) -> Dict[str, Any]:
    home = paos_home(home_dir)
    plugins_dir = home / ".gemini" / "config" / "plugins"
    cfg_path = home / ".gemini" / "config" / "config.json"

    if not plugins_dir.is_dir():
        return {"installed": False, "total_count": 0, "enabled_count": 0, "disabled_count": 0, "enabled_tokens": 0, "disabled_tokens": 0, "plugins": []}

    enabled_map: Dict[str, bool] = {}
    if cfg_path.is_file():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            for k, v in (cfg.get("plugins") or {}).items():
                if isinstance(v, dict) and "enabled" in v:
                    enabled_map[k] = bool(v["enabled"])
        except Exception:
            pass

    items: List[Dict[str, Any]] = []
    enabled_tokens = 0
    disabled_tokens = 0

    for pname in sorted(os.listdir(plugins_dir)):
        pdir = plugins_dir / pname
        if pname.startswith(".") or not pdir.is_dir():
            continue

        is_enabled = enabled_map.get(pname, True)
        skill_tok = 0
        skill_cnt = 0
        psk = pdir / "skills"
        if psk.is_dir():
            for sname in sorted(os.listdir(psk)):
                if sname.startswith("."):
                    continue
                m = _parse_skill_meta(psk / sname)
                skill_tok += m["est_discovery_tokens"]
                skill_cnt += 1

        rule_tok = 0
        rule_cnt = 0
        prules = pdir / "rules"
        if prules.is_dir():
            for rname in sorted(os.listdir(prules)):
                rp = prules / rname
                if rp.is_file() and rname.endswith(".md"):
                    rule_cnt += 1
                    rule_tok += int(rp.stat().st_size / 3.5)

        has_mcp = (pdir / ".mcp.json").is_file() or (pdir / "mcp.json").is_file()
        mcp_tok = 220 if has_mcp else 0
        est = skill_tok + rule_tok + mcp_tok

        if is_enabled:
            enabled_tokens += est
        else:
            disabled_tokens += est

        items.append(
            {
                "name": pname,
                "enabled": is_enabled,
                "skill_count": skill_cnt,
                "rule_count": rule_cnt,
                "has_mcp": has_mcp,
                "estimated_tokens": est,
            }
        )

    return {
        "installed": True,
        "total_count": len(items),
        "enabled_count": sum(1 for x in items if x["enabled"]),
        "disabled_count": sum(1 for x in items if not x["enabled"]),
        "enabled_tokens": enabled_tokens,
        "disabled_tokens": disabled_tokens,
        "plugins": items,
    }


def set_agy_plugins_state(
    plugin_names: Sequence[str],
    enabled: bool,
    home_dir: Optional[Path] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Toggle Antigravity plugins atomically in `~/.gemini/config/config.json` (<5ms, preserves existing keys)."""
    home = paos_home(home_dir)
    info = scan_agy_plugins(home)
    known = {p["name"]: p for p in info["plugins"]}
    changed: List[str] = []
    missing: List[str] = []

    for name in plugin_names:
        if name not in known:
            missing.append(name)
            continue
        if known[name]["enabled"] == enabled:
            continue
        changed.append(name)

    if changed and not dry_run:
        cfg_path = home / ".gemini" / "config" / "config.json"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        data: Dict[str, Any] = {}
        if cfg_path.is_file():
            try:
                parsed = json.loads(cfg_path.read_text(encoding="utf-8"))
                if isinstance(parsed, dict):
                    data = parsed
            except json.JSONDecodeError as exc:
                raise ValueError(f"{cfg_path} JSON 语法损坏: {exc}") from exc

        pmap = data.setdefault("plugins", {})
        if not isinstance(pmap, dict):
            pmap = {}
            data["plugins"] = pmap
        for name in changed:
            existing_entry = pmap.get(name)
            if isinstance(existing_entry, dict):
                existing_entry["enabled"] = enabled
            else:
                pmap[name] = {"enabled": enabled}
        cfg_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    saved_tokens = sum(known[n]["estimated_tokens"] for n in changed) * (-1 if not enabled else 1)
    return {
        "dry_run": dry_run,
        "enabled": enabled,
        "changed": changed,
        "missing": missing,
        "delta_tokens": saved_tokens,
    }


def adopt_skills(
    home_dir: Optional[Path] = None,
    targets: Optional[Sequence[str]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Consolidate skills into `~/.paos/store/skills/` with full-tree hash dedup & 1-hop symlinks."""
    home = paos_home(home_dir)
    target_ids = list(targets) if targets else resolve_targets(None, home, only_installed=True)
    store_dir = home / ".paos" / "store" / "skills"
    snap_dir = home / ".paos" / "snapshots"
    div_backup_root = home / ".paos" / "backups"

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    snapshot_entries: List[Dict[str, Any]] = []
    actions: List[str] = []
    adopted_skills: Set[str] = set()
    adopted_source: Dict[str, Path] = {}
    healed_links: List[str] = []
    backed_up_diverged: List[str] = []

    if not dry_run:
        store_dir.mkdir(parents=True, exist_ok=True)
        snap_dir.mkdir(parents=True, exist_ok=True)

    # Pass 0: Pure read-only snapshot + discover newest physical copy per skill name
    newest_phys: Dict[str, Tuple[float, Path]] = {}
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
                if not is_link and entry.is_dir():
                    md = entry / "SKILL.md"
                    mt = md.stat().st_mtime if md.is_file() else entry.stat().st_mtime
                    if name not in newest_phys or mt > newest_phys[name][0]:
                        newest_phys[name] = (mt, entry)

    # Step 1a: Adopt newest physical copies into `~/.paos/store/skills/<name>` first!
    for name, (_mt, pref_dir) in sorted(newest_phys.items()):
        canonical = store_dir / name
        if canonical.exists() or canonical.is_symlink():
            continue
        actions.append(f"adopt newest dir {pref_dir} -> {canonical}")
        adopted_skills.add(name)
        adopted_source[name] = pref_dir
        if not dry_run:
            shutil.move(str(pref_dir), str(canonical))
            os.symlink(str(canonical), str(pref_dir))

    # Step 1b: Handle remaining physical copies (dedup identical tree hash or backup diverged) & symlink sources
    for hid in target_ids:
        spec = HARNESS_SPECS[hid]
        for rel_dir in (spec["skills"], spec["off"]):
            base = home / rel_dir
            if not base.is_dir():
                continue
            for name in sorted(os.listdir(base)):
                if name.startswith(".") or name.startswith("_"):
                    continue
                entry = base / name
                canonical = store_dir / name
                already_has_canon = canonical.exists() or canonical.is_symlink() or (name in adopted_source)

                if entry.is_symlink():
                    if entry.exists() and not already_has_canon:
                        real_target = entry.resolve()
                        if _inside_external_git_repo(real_target, home):
                            actions.append(f"store link {name} -> {real_target}")
                            adopted_skills.add(name)
                            adopted_source[name] = real_target
                            if not dry_run:
                                os.symlink(str(real_target), str(canonical))
                        elif real_target != canonical:
                            actions.append(f"move resolved {real_target} -> {canonical}")
                            adopted_skills.add(name)
                            adopted_source[name] = real_target
                            if not dry_run:
                                shutil.move(str(real_target), str(canonical))
                                os.symlink(str(canonical), str(real_target))
                elif entry.is_dir():
                    canon_real = canonical.resolve() if canonical.exists() else adopted_source.get(name, canonical)
                    if entry.resolve() != canon_real:
                        h_canon = _skill_tree_hash(canon_real)
                        h_entry = _skill_tree_hash(entry)
                        if h_canon is not None and h_entry is not None and h_canon == h_entry:
                            actions.append(f"dedup identical dir {entry} -> symlink {canonical}")
                            if not dry_run:
                                shutil.rmtree(entry)
                                os.symlink(str(canonical), str(entry))
                        else:
                            b_dst = div_backup_root / f"diverged-{ts}" / hid / name
                            backed_up_diverged.append(f"{hid}:{name}")
                            actions.append(f"backup diverged {entry} -> {b_dst}")
                            if not dry_run:
                                b_dst.parent.mkdir(parents=True, exist_ok=True)
                                shutil.move(str(entry), str(b_dst))
                                os.symlink(str(canonical), str(entry))

    # Pass 2: Rewire all active/off symlinks into direct 1-hop symlinks & heal broken daisy-chains
    for hid in target_ids:
        spec = HARNESS_SPECS[hid]
        for rel_dir in (spec["skills"], spec["off"]):
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
                    cand = _find_heal_candidate(name, home)
                    if cand is not None and _inside_external_git_repo(cand, home):
                        store_has = True
                        if not dry_run and not (canonical.exists() or canonical.is_symlink()):
                            os.symlink(str(cand), str(canonical))

                if not store_has or not entry.is_symlink():
                    continue

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
    if not dry_run and snapshot_entries and (actions or not list(snap_dir.glob("links-*.json"))):
        # Only write a new snapshot when mutations occurred (never overwrite baseline on a no-op 2nd run!)
        baseline = snap_dir / "links-00000000-baseline.json"
        sp = baseline if not baseline.is_file() else (snap_dir / f"links-{ts}.json")
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
    """Restore original pre-adopt topology from baseline snapshot (even after `paos use` profile switches!)."""
    home = paos_home(home_dir)
    snap_dir = home / ".paos" / "snapshots"
    if not snap_dir.is_dir():
        return (False, "未找到快照目录 ~/.paos/snapshots/。")

    baseline = snap_dir / "links-00000000-baseline.json"
    snaps = sorted(snap_dir.glob("links-*.json"))
    chosen_snap = baseline if baseline.is_file() else (snaps[-1] if snaps else None)
    if chosen_snap is None:
        return (False, "未找到任何可回滚的链接拓扑快照。")

    data = json.loads(chosen_snap.read_text(encoding="utf-8"))
    store_dir = home / ".paos" / "store" / "skills"
    backup_dir = home / ".paos" / "backups" / f"pre-restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    target_ids = data.get("targets") or list(HARNESS_ORDER)
    entries = data.get("entries") or []
    snap_paths = {Path(item["path"]) for item in entries}

    # Step 1: Clean up store-managed symlinks created later by `paos use` that did NOT exist in pre-adopt snapshot
    for hid in target_ids:
        if hid not in HARNESS_SPECS:
            continue
        spec = HARNESS_SPECS[hid]
        for rel_dir in (spec["skills"], spec["off"]):
            d = home / rel_dir
            if not d.is_dir():
                continue
            for name in os.listdir(d):
                if name.startswith(".") or name.startswith("_"):
                    continue
                cand = d / name
                if cand not in snap_paths and cand.is_symlink():
                    link_t = os.readlink(cand)
                    if str(store_dir) in link_t:
                        cand.unlink()

    # Step 2: Restore every recorded entry (both symlinks AND original physical directories!)
    restored = 0
    for item in entries:
        p = Path(item["path"])
        p.parent.mkdir(parents=True, exist_ok=True)
        if item["is_symlink"] and item["link_target"]:
            _backup_or_remove_dst(p, backup_dir, item.get("harness", "h"))
            os.symlink(item["link_target"], str(p))
            restored += 1
        elif not item["is_symlink"]:
            canon = store_dir / p.name
            if canon.is_dir() and not canon.is_symlink():
                _backup_or_remove_dst(p, backup_dir, item.get("harness", "h"))
                shutil.copytree(canon, p, symlinks=True)
                restored += 1
            elif canon.is_symlink() and canon.exists():
                _backup_or_remove_dst(p, backup_dir, item.get("harness", "h"))
                shutil.copytree(canon.resolve(), p, symlinks=True)
                restored += 1

    return (True, f"已从快照 {chosen_snap} 完整恢复 {restored} 项技能与链接拓扑。")


def _discover_skill_pool(home: Path, target_ids: Sequence[str]) -> Dict[str, Path]:
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
    include_plugins: bool = False,
    allow_empty: bool = False,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """`nvm use` for AI Agent skills: switch active skills across targeted harnesses in <50ms."""
    home = paos_home(home_dir)
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

    if pool and not desired_names and not allow_empty:
        raise ValueError(
            f"预设 '{profile_name}' 在本机 {len(pool)} 个技能中匹配为 0 个（配置文件: {profiles_file}）。"
            "为防止误清空本机全部技能已中止；请编辑 ~/.paos/skill-profiles.json 添加你的常用技能名，或显式传 `--allow-empty`。"
        )

    store_dir = home / ".paos" / "store" / "skills"
    backup_dir = home / ".paos" / "backups" / f"use-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    per_harness: List[Dict[str, Any]] = []
    skipped_permissions: List[str] = []

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
        if sk_dir.is_dir():
            for name in sorted(current_active & desired_names):
                if (sk_dir / name).is_symlink() and not (sk_dir / name).exists() and name in pool:
                    if name not in to_enable:
                        to_enable.append(name)

        if not dry_run:
            try:
                sk_dir.mkdir(parents=True, exist_ok=True)
                off_dir.mkdir(parents=True, exist_ok=True)

                for name in to_park:
                    src = sk_dir / name
                    if not (src.exists() or src.is_symlink()):
                        continue
                    dst = off_dir / name
                    if src.is_symlink() and dst.is_dir() and not dst.is_symlink():
                        src.unlink()
                    else:
                        _backup_or_remove_dst(dst, backup_dir, f"{hid}-off")
                        shutil.move(str(src), str(dst))

                for name in to_enable:
                    dst = sk_dir / name
                    if dst.is_symlink() and not dst.exists():
                        dst.unlink()
                    if dst.exists():
                        continue
                    off_cand = off_dir / name
                    store_cand = store_dir / name
                    if store_cand.exists():
                        if off_cand.is_symlink():
                            off_cand.unlink()
                        os.symlink(str(store_cand), str(dst))
                    elif off_cand.exists():
                        shutil.move(str(off_cand), str(dst))
                    elif name in pool:
                        os.symlink(str(pool[name]), str(dst))
            except OSError as exc:
                skipped_permissions.append(f"{hid}: {exc}")

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

    agy_plugin_result: Optional[Dict[str, Any]] = None
    if include_plugins:
        plg_info = scan_agy_plugins(home)
        if plg_info["total_count"] > 0:
            plg_patterns = list(cfg.get("always_keep_agy_plugins") or []) + list(
                profiles[profile_name].get("agy_plugins") or []
            )
            want_en: List[str] = []
            want_dis: List[str] = []
            for p in plg_info["plugins"]:
                should_en = any(fnmatch.fnmatch(p["name"], pat) for pat in plg_patterns)
                if should_en and not p["enabled"]:
                    want_en.append(p["name"])
                elif not should_en and p["enabled"]:
                    want_dis.append(p["name"])
            delta_plg = 0
            try:
                if want_en:
                    r_en = set_agy_plugins_state(want_en, enabled=True, home_dir=home, dry_run=dry_run)
                    delta_plg += r_en["delta_tokens"]
                if want_dis:
                    r_dis = set_agy_plugins_state(want_dis, enabled=False, home_dir=home, dry_run=dry_run)
                    delta_plg += r_dis["delta_tokens"]
            except (OSError, ValueError) as exc:
                skipped_permissions.append(f"agy_plugins: {exc}")
            agy_plugin_result = {
                "enabled": want_en,
                "disabled": want_dis,
                "delta_tokens": delta_plg,
            }

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
        "agy_plugins": agy_plugin_result,
        "skipped_permissions": skipped_permissions,
    }


def prune_claude_state_json(home_dir: Optional[Path] = None, dry_run: bool = False) -> Dict[str, Any]:
    """Safely prune stale deleted project caches from `~/.claude.json` preserving permissions & symlinks."""
    home = paos_home(home_dir)
    cjson_entry = home / ".claude.json"
    if not cjson_entry.is_file():
        return {"pruned_projects": [], "reclaimed_bytes": 0, "backup_path": None}

    cjson = cjson_entry.resolve() if cjson_entry.is_symlink() else cjson_entry
    try:
        old_txt = cjson.read_text(encoding="utf-8")
        data = json.loads(old_txt)
    except Exception:
        return {"pruned_projects": [], "reclaimed_bytes": 0, "backup_path": None}

    projects = data.get("projects")
    if not isinstance(projects, dict) or not projects:
        return {"pruned_projects": [], "reclaimed_bytes": 0, "backup_path": None}

    pruned: List[str] = []
    kept_projects: Dict[str, Any] = {}
    for proj_key, proj_val in projects.items():
        if isinstance(proj_val, dict) and proj_val.get("mcpServers"):
            kept_projects[proj_key] = proj_val
            continue
        if proj_key.startswith("/Volumes/"):
            vol_parts = Path(proj_key).parts
            if len(vol_parts) >= 3 and not (Path("/Volumes") / vol_parts[2]).exists():
                kept_projects[proj_key] = proj_val
                continue
        try:
            exists = Path(proj_key).exists()
        except OSError:
            exists = True
        if exists:
            kept_projects[proj_key] = proj_val
        else:
            pruned.append(proj_key)

    if not pruned:
        return {"pruned_projects": [], "reclaimed_bytes": 0, "backup_path": None}

    new_data = dict(data)
    new_data["projects"] = kept_projects
    new_txt = json.dumps(new_data, ensure_ascii=False, indent=2) + "\n"
    reclaimed = max(0, len(old_txt.encode("utf-8")) - len(new_txt.encode("utf-8")))
    backup_path: Optional[str] = None

    if not dry_run:
        orig_mode = (cjson.stat().st_mode & 0o777) or 0o600
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        bdir = home / ".claude" / "backups"
        bdir.mkdir(parents=True, mode=0o700, exist_ok=True)
        bp = bdir / f"claude-state-{ts}.json.bak"
        shutil.copy2(cjson, bp)
        os.chmod(bp, orig_mode)
        backup_path = str(bp)

        fd, tmp_name = tempfile.mkstemp(prefix=".claude.json.paos-", dir=str(cjson.parent))
        try:
            os.chmod(tmp_name, orig_mode)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(new_txt)
            os.replace(tmp_name, str(cjson))
        except Exception:
            Path(tmp_name).unlink(missing_ok=True)
            raise

    return {
        "pruned_projects": pruned,
        "reclaimed_bytes": reclaimed,
        "backup_path": backup_path,
    }


def clean_harnesses(
    home_dir: Optional[Path] = None,
    targets: Optional[Sequence[str]] = None,
    heal_links: bool = True,
    prune_claude_state: bool = False,
    min_tmp_age_sec: int = 0,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Safely clean orphan `.tmp-*` crash files, `.DS_Store`, stale `.claude.json` projects, and broken symlinks."""
    home = paos_home(home_dir)
    target_ids = list(targets) if targets else resolve_targets(None, home, only_installed=True)

    removed_orphans: List[str] = []
    reclaimed_bytes = 0
    healed_symlinks: List[str] = []
    quarantined_symlinks: List[str] = []
    skipped_permissions: List[str] = []
    now_ts = time.time()

    for hid in target_ids:
        spec = HARNESS_SPECS[hid]
        sk_dir = home / spec["skills"]
        off_dir = home / spec["off"]

        for pat in spec["orphan_globs"]:
            for match in sorted(home.glob(pat)):
                if match.is_file() or match.is_symlink():
                    try:
                        st = match.lstat()
                        if min_tmp_age_sec > 0 and (now_ts - st.st_mtime) < min_tmp_age_sec:
                            continue
                        sz = st.st_size
                    except OSError:
                        sz = 0
                    if not dry_run:
                        try:
                            match.unlink()
                        except OSError as exc:
                            skipped_permissions.append(f"{match}: {exc}")
                            continue
                    removed_orphans.append(str(match.relative_to(home)))
                    reclaimed_bytes += sz

        if sk_dir.is_dir():
            for name in sorted(os.listdir(sk_dir)):
                entry = sk_dir / name
                if name == ".DS_Store" and entry.is_file():
                    try:
                        sz = entry.stat().st_size
                    except OSError:
                        sz = 0
                    if not dry_run:
                        try:
                            entry.unlink()
                        except OSError as exc:
                            skipped_permissions.append(f"{entry}: {exc}")
                            continue
                    reclaimed_bytes += sz
                    removed_orphans.append(str(entry.relative_to(home)))
                    continue

                if name.startswith("."):
                    continue

                if entry.is_symlink() and not entry.exists():
                    cand = _find_heal_candidate(name, home) if heal_links else None
                    if cand is not None:
                        if not dry_run:
                            try:
                                entry.unlink()
                                os.symlink(str(cand), str(entry))
                            except OSError as exc:
                                skipped_permissions.append(f"{entry}: {exc}")
                                continue
                        healed_symlinks.append(f"{hid}:{name} -> {cand}")
                    else:
                        if not dry_run:
                            try:
                                q_dir = off_dir / "_broken"
                                q_dir.mkdir(parents=True, exist_ok=True)
                                q_dst = q_dir / name
                                if q_dst.is_symlink() or q_dst.is_file():
                                    q_dst.unlink()
                                elif q_dst.is_dir():
                                    shutil.rmtree(q_dst)
                                shutil.move(str(entry), str(q_dst))
                            except OSError as exc:
                                skipped_permissions.append(f"{entry}: {exc}")
                                continue
                        quarantined_symlinks.append(f"{hid}:{name}")

    prune_res: Dict[str, Any] = {"pruned_projects": [], "reclaimed_bytes": 0, "backup_path": None}
    if prune_claude_state:
        try:
            prune_res = prune_claude_state_json(home, dry_run=dry_run)
            reclaimed_bytes += prune_res["reclaimed_bytes"]
        except OSError as exc:
            skipped_permissions.append(f".claude.json: {exc}")

    return {
        "dry_run": dry_run,
        "targets": target_ids,
        "removed_orphan_files": removed_orphans,
        "reclaimed_bytes": reclaimed_bytes,
        "healed_symlinks": healed_symlinks,
        "quarantined_broken_symlinks": quarantined_symlinks,
        "pruned_claude_projects": prune_res["pruned_projects"],
        "claude_state_backup": prune_res["backup_path"],
        "skipped_permissions": skipped_permissions,
    }


# =============================================================================
# Single-Harness Claude Compatibility Helpers (safe path-validated wrappers)
# =============================================================================


def list_skills(home_dir: Optional[Path] = None) -> Dict[str, Any]:
    home = paos_home(home_dir)
    active_dir = home / ".claude" / "skills"
    off_dir = home / ".claude" / "skills-off"

    active = [
        _parse_skill_meta(active_dir / n)
        for n in (sorted(os.listdir(active_dir)) if active_dir.is_dir() else [])
        if not n.startswith(".")
    ]
    parked = [
        _parse_skill_meta(off_dir / n)
        for n in (sorted(os.listdir(off_dir)) if off_dir.is_dir() else [])
        if not n.startswith(".") and not n.startswith("_")
    ]
    return {
        "active_dir": str(active_dir),
        "off_dir": str(off_dir),
        "active_count": len(active),
        "parked_count": len(parked),
        "broken_active_count": sum(1 for s in active if s["broken"]),
        "estimated_active_tokens": sum(s["est_discovery_tokens"] for s in active),
        "active": active,
        "parked": parked,
    }


def _move_skill_entries(
    names: Sequence[str], src_dir: Path, dst_dir: Path, backup_dir: Path
) -> Tuple[List[str], List[str]]:
    dst_dir.mkdir(parents=True, exist_ok=True)
    moved: List[str] = []
    missing: List[str] = []
    for raw_name in names:
        name = _validate_skill_name(raw_name)
        src = src_dir / name
        if not (src.exists() or src.is_symlink()):
            missing.append(name)
            continue
        dst = dst_dir / name
        if src.is_symlink() and dst.is_dir() and not dst.is_symlink():
            src.unlink()
        else:
            _backup_or_remove_dst(dst, backup_dir, "claude")
            shutil.move(str(src), str(dst))
        moved.append(name)
    return (moved, missing)


def park_skills(names: Sequence[str], home_dir: Optional[Path] = None) -> Tuple[List[str], List[str]]:
    home = paos_home(home_dir)
    return _move_skill_entries(
        names,
        home / ".claude" / "skills",
        home / ".claude" / "skills-off",
        home / ".paos" / "backups" / "park",
    )


def enable_skills(names: Sequence[str], home_dir: Optional[Path] = None) -> Tuple[List[str], List[str]]:
    home = paos_home(home_dir)
    return _move_skill_entries(
        names,
        home / ".claude" / "skills-off",
        home / ".claude" / "skills",
        home / ".paos" / "backups" / "enable",
    )


def clean_broken_skills(home_dir: Optional[Path] = None) -> List[str]:
    info = list_skills(home_dir)
    broken = [s["name"] for s in info["active"] if s["broken"]]
    if broken:
        park_skills(broken, home_dir)
    return broken


def apply_profile(
    profile_name: str,
    profiles_file: Path,
    home_dir: Optional[Path] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    res = use_profile(
        profile_name,
        profiles_file,
        home_dir=home_dir,
        targets=["claude"],
        allow_empty=True,
        dry_run=dry_run,
    )
    h = res["harnesses"][0]
    return {
        "profile": profile_name,
        "dry_run": dry_run,
        "to_park": h["to_park"],
        "to_enable": h["to_enable"],
        "resulting_active": res["desired_skills"],
    }
