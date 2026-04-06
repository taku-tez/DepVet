"""Archive unpacker for wheel, sdist, and npm tarballs."""

from __future__ import annotations

import logging
import tarfile
import zipfile
from inspect import signature
from pathlib import Path

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
    name_lower = archive_path.name.lower()
    last_suffix = archive_path.suffix.lower()

    if last_suffix in (".whl", ".zip", ".jar"):
        return _unpack_zip(archive_path, dest_dir)
    elif name_lower.endswith(".tar.gz") or last_suffix == ".tgz":
        return _unpack_tarball(archive_path, dest_dir)
    elif last_suffix == ".crate":
        # Cargo .crate files are tar.gz archives
        return _unpack_tarball(archive_path, dest_dir)
    else:
        raise ValueError(f"Unsupported archive format: {archive_path.name}")


# Safety limits for archive extraction
_MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 500 MB
_MAX_FILE_COUNT = 10_000


def _safe_zip_path(name: str, out: Path) -> "Path | None":
    """Return resolved path inside out, or None if unsafe."""
    target = (out / name).resolve()
    try:
        target.relative_to(out.resolve())
    except ValueError:
        return None
    return target


def _unpack_zip(archive_path: Path, dest_dir: Path) -> Path:
    """Unpack a ZIP or wheel archive with safety guards."""
    out = dest_dir / archive_path.stem
    out.mkdir(parents=True, exist_ok=True)
    total_bytes = 0
    file_count = 0
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            if info.filename.startswith("/"):
                logger.warning(f"Skipping unsafe zip entry: {info.filename}")
                continue
            dest_path = _safe_zip_path(info.filename, out)
            if dest_path is None:
                logger.warning(f"Skipping path traversal: {info.filename}")
                continue
            total_bytes += info.file_size
            if total_bytes > _MAX_UNCOMPRESSED_BYTES:
                logger.warning("Zip bomb detected: uncompressed size exceeded 500 MB")
                break
            file_count += 1
            if file_count > _MAX_FILE_COUNT:
                logger.warning("Too many files in archive (>10000)")
                break
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            if info.is_dir():
                dest_path.mkdir(exist_ok=True)
            else:
                with zf.open(info) as src, open(dest_path, "wb") as dst:
                    dst.write(src.read())
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
            # Skip symlinks and hardlinks (security risk)
            if member.issym() or member.islnk():
                logger.warning(f"Skipping symlink in tarball: {member.name}")
                continue
            # Skip absolute paths
            if Path(member.name).is_absolute():
                continue
            members.append(member)
        # Zip bomb guard for tarballs
        total_size = sum(m.size for m in members)
        if total_size > _MAX_UNCOMPRESSED_BYTES:
            logger.warning("Tarball too large (>500 MB uncompressed), truncating")
            members = members[:_MAX_FILE_COUNT]
        if "filter" in signature(tf.extractall).parameters:
            tf.extractall(out, members=members, filter="data")
        else:
            tf.extractall(out, members=members)  # nosec B202 — members validated above

    return out
