"""Resolve bundled template/config assets across both git checkouts and `uv tool` / `pip` installs."""

from __future__ import annotations

from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def resolve_asset(repo_rel_path: str, asset_name: str) -> Path:
    repo_cand = repo_root() / repo_rel_path
    if repo_cand.is_file():
        return repo_cand
    pkg_cand = Path(__file__).resolve().parent / "assets" / asset_name
    if pkg_cand.is_file():
        return pkg_cand
    raise FileNotFoundError(f"未找到内置资源文件: {asset_name}")
