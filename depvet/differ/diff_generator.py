"""Diff generator between two unpacked package versions."""

from __future__ import annotations

import difflib
import logging
from pathlib import Path
from typing import Optional

from depvet.differ.chunker import DiffChunk, DiffChunker, DiffFile
from depvet.models.verdict import DiffStats

logger = logging.getLogger(__name__)

BINARY_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".so",
    ".dll",
    ".exe",
    ".bin",
    ".dat",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".whl",
}


def _is_binary_file(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
        return b"\x00" in chunk
    except (OSError, IOError):
        return True


def _read_lines(path: Path) -> list[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except (OSError, IOError):
        return []


def _collect_files(base_dir: Path) -> dict[str, Path]:
    """Return {relative_path: absolute_path} for all files under base_dir."""
    result: dict[str, Path] = {}
    if not base_dir.exists():
        return result
    for p in base_dir.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(base_dir))
            result[rel] = p
    return result


def generate_diff(
    old_dir: Path,
    new_dir: Path,
    max_chunk_tokens: int = 8000,
    chunker: Optional[DiffChunker] = None,
) -> tuple[list[DiffChunk], DiffStats]:
    """
    Generate a list of DiffChunks and DiffStats between two package directories.
    """
    old_files = _collect_files(old_dir)
    new_files = _collect_files(new_dir)

    all_paths = sorted(set(old_files.keys()) | set(new_files.keys()))

    diff_files: list[DiffFile] = []
    stats = DiffStats(
        files_changed=0,
        lines_added=0,
        lines_removed=0,
        binary_files=[],
        new_files=[],
        deleted_files=[],
    )

    for rel_path in all_paths:
        old_path = old_files.get(rel_path)
        new_path = new_files.get(rel_path)

        is_new = old_path is None
        is_deleted = new_path is None

        if is_new:
            stats.new_files.append(rel_path)
        if is_deleted:
            stats.deleted_files.append(rel_path)

        # Check for binary
        check_path = new_path or old_path
        if _is_binary_file(check_path):  # type: ignore[arg-type]
            stats.binary_files.append(rel_path)
            diff_files.append(
                DiffFile(
                    path=rel_path,
                    content="",
                    is_binary=True,
                    is_new=is_new,
                    is_deleted=is_deleted,
                )
            )
            stats.files_changed += 1
            continue

        old_lines = _read_lines(old_path) if old_path else []
        new_lines = _read_lines(new_path) if new_path else []

        diff_lines = list(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
                lineterm="",
            )
        )

        if not diff_lines and not is_new and not is_deleted:
            continue

        added = sum(1 for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++"))
        removed = sum(1 for ln in diff_lines if ln.startswith("-") and not ln.startswith("---"))
        stats.lines_added += added
        stats.lines_removed += removed
        if diff_lines or is_new or is_deleted:
            stats.files_changed += 1

        diff_files.append(
            DiffFile(
                path=rel_path,
                content="\n".join(diff_lines),
                is_binary=False,
                is_new=is_new,
                is_deleted=is_deleted,
            )
        )

    if chunker is None:
        chunker = DiffChunker(max_tokens=max_chunk_tokens)

    chunks = chunker.chunk(diff_files)
    return chunks, stats


def format_diff_markdown(chunks: list[DiffChunk], stats: DiffStats) -> str:
    """Format diff chunks as a markdown document."""
    lines = [
        "# Package Diff",
        f"- Files changed: {stats.files_changed}",
        f"- Lines added: {stats.lines_added}",
        f"- Lines removed: {stats.lines_removed}",
        f"- New files: {', '.join(stats.new_files) or 'none'}",
        f"- Deleted files: {', '.join(stats.deleted_files) or 'none'}",
        f"- Binary files: {', '.join(stats.binary_files) or 'none'}",
        "",
    ]
    for i, chunk in enumerate(chunks):
        lines.append(f"## Chunk {i + 1}/{len(chunks)}")
        lines.append("```diff")
        lines.append(chunk.content)
        lines.append("```")
        lines.append("")
    return "\n".join(lines)
