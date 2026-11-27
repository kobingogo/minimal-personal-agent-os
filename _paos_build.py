"""Zero-dependency PEP 517 build backend for minimal-personal-agent-os (`paos`).

Builds compliant `.whl` and `.tar.gz` artifacts using 100% Python 3.9+ stdlib (`zipfile`,
`tarfile`, `hashlib`, `base64`), enabling offline/air-gapped `uv tool install` & `pip install`
without requiring `setuptools`, `wheel`, or `hatchling`.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import tarfile
from typing import Any, Dict, List, Optional, Tuple
import zipfile

DIST_NAME = "minimal_personal_agent_os"
PKG_NAME = "minimal-personal-agent-os"
VERSION = "0.1.0"


def _root() -> Path:
    return Path(__file__).resolve().parent


def _b64_sha256(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _metadata_bytes(root: Path) -> bytes:
    readme = (root / "README.md").read_text(encoding="utf-8") if (root / "README.md").is_file() else ""
    headers = [
        "Metadata-Version: 2.1",
        f"Name: {PKG_NAME}",
        f"Version: {VERSION}",
        "Summary: Zero-dependency Personal AI Agent OS control plane for Claude Code, Codex, Antigravity & Cursor",
        "Author: kobingogo",
        "License: MIT",
        "Requires-Python: >=3.9",
        "Description-Content-Type: text/markdown",
        "",
        readme,
    ]
    return "\n".join(headers).encode("utf-8")


def get_requires_for_build_wheel(config_settings: Optional[Dict[str, Any]] = None) -> List[str]:
    return []


def get_requires_for_build_sdist(config_settings: Optional[Dict[str, Any]] = None) -> List[str]:
    return []


def build_wheel(
    wheel_directory: str,
    config_settings: Optional[Dict[str, Any]] = None,
    metadata_directory: Optional[str] = None,
) -> str:
    root = _root()
    out_dir = Path(wheel_directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    wheel_name = f"{DIST_NAME}-{VERSION}-py3-none-any.whl"
    wheel_path = out_dir / wheel_name
    dist_info = f"{DIST_NAME}-{VERSION}.dist-info"

    records: List[Tuple[str, str, str]] = []

    def add_bytes(zf: zipfile.ZipFile, arcname: str, payload: bytes) -> None:
        zi = zipfile.ZipInfo(arcname, date_time=(2026, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = 0o644 << 16
        zf.writestr(zi, payload)
        records.append((arcname, _b64_sha256(payload), str(len(payload))))

    pkg_root = root / "lib" / "paos"
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(pkg_root.rglob("*")):
            if not file_path.is_file() or "__pycache__" in file_path.parts or file_path.suffix == ".pyc":
                continue
            rel = "paos/" + file_path.relative_to(pkg_root).as_posix()
            add_bytes(zf, rel, file_path.read_bytes())

        add_bytes(zf, f"{dist_info}/METADATA", _metadata_bytes(root))
        wheel_meta = (
            "Wheel-Version: 1.0\n"
            "Generator: _paos_build (stdlib)\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode("utf-8")
        add_bytes(zf, f"{dist_info}/WHEEL", wheel_meta)
        entry_pts = b"[console_scripts]\npaos = paos.cli:main\n"
        add_bytes(zf, f"{dist_info}/entry_points.txt", entry_pts)
        if (root / "LICENSE").is_file():
            add_bytes(zf, f"{dist_info}/LICENSE", (root / "LICENSE").read_bytes())

        record_lines = [f"{p},{h},{sz}" for p, h, sz in records]
        record_lines.append(f"{dist_info}/RECORD,,")
        zi_rec = zipfile.ZipInfo(f"{dist_info}/RECORD", date_time=(2026, 1, 1, 0, 0, 0))
        zi_rec.compress_type = zipfile.ZIP_DEFLATED
        zi_rec.external_attr = 0o644 << 16
        zf.writestr(zi_rec, ("\n".join(record_lines) + "\n").encode("utf-8"))

    return wheel_name


def build_sdist(sdist_directory: str, config_settings: Optional[Dict[str, Any]] = None) -> str:
    root = _root()
    out_dir = Path(sdist_directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    sdist_name = f"{DIST_NAME}-{VERSION}.tar.gz"
    sdist_path = out_dir / sdist_name
    prefix = f"{DIST_NAME}-{VERSION}"

    with tarfile.open(sdist_path, "w:gz") as tf:
        for item in sorted(root.rglob("*")):
            rel_parts = item.relative_to(root).parts
            if (
                not item.is_file()
                or ".git" in rel_parts
                or "__pycache__" in rel_parts
                or item.suffix == ".pyc"
            ):
                continue
            tf.add(item, arcname=os.path.join(prefix, item.relative_to(root).as_posix()))

    return sdist_name
