"""Lockfile parsers for importing dependencies into the watchlist.

Supports:
  - package-lock.json  (npm v2/v3)
  - yarn.lock          (classic v1 + berry v2+)
  - Pipfile.lock       (pipenv)
  - poetry.lock        (poetry)
  - go.sum             (Go modules)
  - Cargo.lock         (Rust/Cargo)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from depvet.watchlist.explicit import WatchlistEntry

logger = logging.getLogger(__name__)


def parse_lockfile(path: str) -> list[WatchlistEntry]:
    """Auto-detect lockfile format and parse dependencies.

    Returns a list of WatchlistEntry with name, ecosystem, and version.
    """
    p = Path(path)
    fname = p.name.lower()

    if fname == "package-lock.json":
        return _parse_package_lock(p)
    if fname == "yarn.lock":
        return _parse_yarn_lock(p)
    if fname == "pipfile.lock":
        return _parse_pipfile_lock(p)
    if fname == "poetry.lock":
        return _parse_poetry_lock(p)
    if fname == "go.sum":
        return _parse_go_sum(p)
    if fname == "cargo.lock":
        return _parse_cargo_lock(p)

    logger.warning(f"Unknown lockfile format: {fname}")
    return []


# ─── npm: package-lock.json ──────────────────────────────────────────────────


def _parse_package_lock(path: Path) -> list[WatchlistEntry]:
    """Parse npm package-lock.json (v2/v3 lockfileVersion)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to parse {path}: {e}")
        return []

    entries: list[WatchlistEntry] = []
    seen: set[str] = set()

    # v2/v3: "packages" key with "" as root + nested paths
    packages = data.get("packages", {})
    if packages:
        for pkg_path, info in packages.items():
            if not pkg_path:  # root package
                continue
            # Extract package name from path: "node_modules/lodash" or nested
            name = info.get("name") or pkg_path.rsplit("node_modules/", 1)[-1]
            version = info.get("version", "")
            if name and name not in seen:
                seen.add(name)
                entries.append(WatchlistEntry(name=name, ecosystem="npm", current_version=version))
        return entries

    # v1 fallback: "dependencies" key
    deps = data.get("dependencies", {})
    for name, info in deps.items():
        version = info.get("version", "") if isinstance(info, dict) else ""
        if name not in seen:
            seen.add(name)
            entries.append(WatchlistEntry(name=name, ecosystem="npm", current_version=version))

    return entries


# ─── yarn: yarn.lock ─────────────────────────────────────────────────────────

# yarn v1: `"lodash@^4.17.21":\n  version "4.17.21"\n`
_YARN_V1_HEADER = re.compile(r'^"?(@?[^@\s]+)@')
_YARN_V1_VERSION = re.compile(r'^\s+version\s+"([^"]+)"')

# yarn berry (v2+): `"lodash@npm:^4.17.21":\n  version: 4.17.21\n`
_YARN_BERRY_HEADER = re.compile(r'^"?(@?[^@\s]+)@(?:npm:)')
_YARN_BERRY_VERSION = re.compile(r'^\s+version:\s+(.+)')


def _parse_yarn_lock(path: Path) -> list[WatchlistEntry]:
    """Parse yarn.lock (v1 classic + v2/berry)."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.error(f"Failed to read {path}: {e}")
        return []

    entries: list[WatchlistEntry] = []
    seen: set[str] = set()
    current_name: str | None = None

    for line in content.splitlines():
        # Try berry format first, then v1
        m = _YARN_BERRY_HEADER.match(line) or _YARN_V1_HEADER.match(line)
        if m:
            current_name = m.group(1)
            continue

        if current_name:
            vm = _YARN_BERRY_VERSION.match(line) or _YARN_V1_VERSION.match(line)
            if vm:
                version = vm.group(1).strip().strip('"')
                if current_name not in seen:
                    seen.add(current_name)
                    entries.append(WatchlistEntry(name=current_name, ecosystem="npm", current_version=version))
                current_name = None

    return entries


# ─── pipenv: Pipfile.lock ────────────────────────────────────────────────────


def _parse_pipfile_lock(path: Path) -> list[WatchlistEntry]:
    """Parse Pipfile.lock (JSON with 'default' and 'develop' sections)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to parse {path}: {e}")
        return []

    entries: list[WatchlistEntry] = []
    seen: set[str] = set()

    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            version = info.get("version", "").lstrip("=")
            if name not in seen:
                seen.add(name)
                entries.append(WatchlistEntry(name=name, ecosystem="pypi", current_version=version))

    return entries


# ─── poetry: poetry.lock ─────────────────────────────────────────────────────

_POETRY_PKG_RE = re.compile(r'^\[\[package\]\]')
_POETRY_NAME_RE = re.compile(r'^name\s*=\s*"([^"]+)"')
_POETRY_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"')


def _parse_poetry_lock(path: Path) -> list[WatchlistEntry]:
    """Parse poetry.lock (TOML-like [[package]] sections)."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.error(f"Failed to read {path}: {e}")
        return []

    entries: list[WatchlistEntry] = []
    seen: set[str] = set()
    current_name: str | None = None
    current_version: str = ""

    for line in content.splitlines():
        if _POETRY_PKG_RE.match(line):
            # Save previous package
            if current_name and current_name not in seen:
                seen.add(current_name)
                entries.append(WatchlistEntry(name=current_name, ecosystem="pypi", current_version=current_version))
            current_name = None
            current_version = ""
            continue

        m = _POETRY_NAME_RE.match(line)
        if m:
            current_name = m.group(1)
            continue

        m = _POETRY_VERSION_RE.match(line)
        if m:
            current_version = m.group(1)

    # Last package
    if current_name and current_name not in seen:
        entries.append(WatchlistEntry(name=current_name, ecosystem="pypi", current_version=current_version))

    return entries


# ─── Go: go.sum ──────────────────────────────────────────────────────────────

_GO_SUM_RE = re.compile(r'^(?P<module>\S+)\s+v(?P<version>[^\s/]+?)(?:/go\.mod)?\s+h1:')


def _parse_go_sum(path: Path) -> list[WatchlistEntry]:
    """Parse go.sum (each line: module version hash)."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.error(f"Failed to read {path}: {e}")
        return []

    entries: list[WatchlistEntry] = []
    seen: set[str] = set()

    for line in content.splitlines():
        m = _GO_SUM_RE.match(line)
        if m:
            module = m.group("module")
            version = m.group("version")
            if module not in seen:
                seen.add(module)
                entries.append(WatchlistEntry(name=module, ecosystem="go", current_version=version))

    return entries


# ─── Rust: Cargo.lock ────────────────────────────────────────────────────────

_CARGO_LOCK_NAME_RE = re.compile(r'^name\s*=\s*"([^"]+)"')
_CARGO_LOCK_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"')


def _parse_cargo_lock(path: Path) -> list[WatchlistEntry]:
    """Parse Cargo.lock (TOML [[package]] sections)."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.error(f"Failed to read {path}: {e}")
        return []

    entries: list[WatchlistEntry] = []
    seen: set[str] = set()
    current_name: str | None = None

    for line in content.splitlines():
        if line.strip() == "[[package]]":
            current_name = None
            continue

        m = _CARGO_LOCK_NAME_RE.match(line)
        if m:
            current_name = m.group(1)
            continue

        m = _CARGO_LOCK_VERSION_RE.match(line)
        if m and current_name and current_name not in seen:
            seen.add(current_name)
            entries.append(WatchlistEntry(name=current_name, ecosystem="cargo", current_version=m.group(1)))
            current_name = None

    return entries
