"""Version ordering helpers for registry monitors."""

from __future__ import annotations

from functools import lru_cache
import re

from packaging.version import InvalidVersion, Version


_SEMVER_RE = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)"
    r"(?:\.(?P<minor>0|[1-9]\d*))?"
    r"(?:\.(?P<patch>0|[1-9]\d*))?"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?"
    r"(?:\+[0-9A-Za-z.-]+)?$"
)


@lru_cache(maxsize=2048)
def _pep440_key(version: str) -> tuple[int, object]:
    try:
        return (0, Version(version))
    except InvalidVersion:
        return (1, version)


def _parse_prerelease(prerelease: str) -> tuple[tuple[int, object], ...]:
    parsed: list[tuple[int, object]] = []
    for part in prerelease.split("."):
        if part.isdigit():
            parsed.append((0, int(part)))
        else:
            parsed.append((1, part))
    return tuple(parsed)


@lru_cache(maxsize=2048)
def _semver_key(version: str) -> tuple[int, tuple[int, int, int], tuple[object, ...], str]:
    match = _SEMVER_RE.match(version)
    if not match:
        return (1, (0, 0, 0), (0,), version)

    core = (
        int(match.group("major")),
        int(match.group("minor") or 0),
        int(match.group("patch") or 0),
    )
    prerelease = match.group("prerelease")
    if prerelease is None:
        prerelease_key: tuple[object, ...] = (1,)
    else:
        prerelease_key = (0, _parse_prerelease(prerelease))
    return (0, core, prerelease_key, version)


def sort_versions(versions: list[str], ecosystem: str) -> list[str]:
    """Sort versions using ecosystem-aware semantics."""
    if ecosystem == "pypi":
        return sorted(versions, key=_pep440_key)
    if ecosystem in {"npm", "go", "cargo"}:
        return sorted(versions, key=_semver_key)
    return sorted(versions)
