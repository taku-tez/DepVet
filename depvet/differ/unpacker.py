"""Archive unpacker for wheel, sdist, and npm tarballs."""

from __future__ import annotations

import logging
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def unpack(archive_path: Path, dest_dir: Path) -> Path:
    """
    Unpack an archive to dest_dir.

    Supports:
    - .whl (wheel = zip)
    - .tar.gz / .tgz (sdist, npm)
    - .zip

    Returns the path to the unpacked directory.
    """
    suffix = "".join(archive_path.suffixes).lower()

    if suffix in (".whl", ".zip") or archive_path.suffix.lower() in (".whl", ".zip"):
        return _unpack_zip(archive_path, dest_dir)
    elif suffix in (".tar.gz", ".tgz") or archive_path.name.endswith(".tar.gz"):
        return _unpack_tarball(archive_path, dest_dir)
    elif archive_path.suffix.lower() == ".crate":
        # Cargo .crate files are tar.gz archives
        return _unpack_tarball(archive_path, dest_dir)
    else:
        raise ValueError(f"Unsupported archive format: {archive_path.name}")


def _unpack_zip(archive_path: Path, dest_dir: Path) -> Path:
    """Unpack a ZIP or wheel archive."""
    out = dest_dir / archive_path.stem
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "r") as zf:
        zf.extractall(out)
    return out


def _unpack_tarball(archive_path: Path, dest_dir: Path) -> Path:
    """Unpack a tar.gz archive (sdist or npm tarball)."""
    # Determine output dir name
    name = archive_path.name
    if name.endswith(".tar.gz"):
        stem = name[:-7]
    elif name.endswith(".tgz"):
        stem = name[:-4]
    else:
        stem = archive_path.stem

    out = dest_dir / stem
    out.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive_path, "r:gz") as tf:
        # Safety: filter out absolute paths and traversal attempts
        members = []
        for member in tf.getmembers():
            # Strip leading path components (npm wraps in 'package/')
            parts = Path(member.name).parts
            if parts and parts[0] in ("package", "."):
                member.name = str(Path(*parts[1:])) if len(parts) > 1 else member.name
            if ".." in Path(member.name).parts:
                continue
            members.append(member)
        tf.extractall(out, members=members)  # type: ignore[call-arg]

    return out
