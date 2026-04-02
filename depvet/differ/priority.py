"""Priority file control for diff analysis."""

from __future__ import annotations

import fnmatch
from pathlib import Path

from depvet.config.defaults import PRIORITY_FILES, SKIP_PATTERNS


def is_priority(filepath: str) -> bool:
    """Check if a file is in the priority list."""
    name = Path(filepath).name
    for pf in PRIORITY_FILES:
        if fnmatch.fnmatch(name, pf) or name == pf:
            return True
    return False


def should_skip(filepath: str) -> bool:
    """Check if a file should be skipped."""
    name = Path(filepath).name
    parts = filepath.replace("\\", "/").split("/")
    for pattern in SKIP_PATTERNS:
        if pattern.endswith("/"):
            # directory pattern
            dir_name = pattern.rstrip("/")
            if dir_name in parts:
                return True
        elif fnmatch.fnmatch(name, pattern):
            return True
    return False


def priority_sort_key(filepath: str) -> tuple[int, str]:
    """Sort key: priority files first (lower index = higher priority), then alphabetical."""
    name = Path(filepath).name
    for i, pf in enumerate(PRIORITY_FILES):
        if fnmatch.fnmatch(name, pf) or name == pf:
            return (i, filepath)
    return (len(PRIORITY_FILES), filepath)
