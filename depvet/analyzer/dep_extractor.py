"""
Dependency extractor: detects newly added dependencies from package manifest diffs.

Why this matters:
  The axios attack (2026-03-30) added ONLY plain-crypto-js@4.2.1 to package.json.
  No source code changed. Standard diff scanners miss this.

  This module:
  1. Parses package.json / pyproject.toml / setup.cfg diffs
  2. Extracts newly-added dependency names+versions
  3. Returns them for:
     a) Known-bad DB lookup
     b) Automatic watchlist addition (scan them too)
     c) Version signal escalation (new unknown dep = MEDIUM signal)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class NewDependency:
    """A newly added dependency detected from a manifest diff."""
    name: str
    version_spec: str        # e.g. "^4.2.1", ">=1.0", "*"
    ecosystem: str           # "npm" | "pypi"
    manifest_file: str       # "package.json", "pyproject.toml", etc.
    is_dev: bool = False     # devDependencies / dev extras
    line_number: Optional[int] = None


# ─── npm / package.json ────────────────────────────────────────────────────

_NPM_DEP_RE = re.compile(
    r"""^\s*"(?P<name>@?[a-zA-Z0-9_\-./]+)"\s*:\s*"(?P<version>[^"]+)"""
)

_NPM_SECTION_RE = re.compile(
    r'"(?P<section>dependencies|devDependencies|peerDependencies|optionalDependencies)"\s*:\s*\{'
)


def _extract_npm_deps(diff_content: str, filepath: str = "package.json") -> list[NewDependency]:
    """Extract newly added npm dependencies from a package.json diff."""
    deps: list[NewDependency] = []
    current_section = "dependencies"
    line_number = 0

    for raw in diff_content.splitlines():
        line_number += 1

        # Track which section we're in
        section_m = _NPM_SECTION_RE.search(raw)
        if section_m:
            current_section = section_m.group("section")
            continue

        if not raw.startswith("+") or raw.startswith("+++"):
            continue

        line = raw[1:]
        m = _NPM_DEP_RE.match(line)
        if m:
            name = m.group("name")
            version = m.group("version")
            # Skip clearly internal/test packages
            if name.startswith("//") or name == "":
                continue
            deps.append(NewDependency(
                name=name,
                version_spec=version,
                ecosystem="npm",
                manifest_file=filepath,
                is_dev=current_section != "dependencies",
                line_number=line_number,
            ))

    return deps


# ─── PyPI / pyproject.toml ─────────────────────────────────────────────────

_PYPI_DEP_RE = re.compile(
    r"""^\s*"?(?P<name>[A-Za-z0-9_\-\.]+)\s*(?P<version>[><=!~\^][^"#,\n]*)?"""
)

_PYPI_EXTRAS_SECTION_RE = re.compile(
    r'^\[tool\.(?:poetry|hatch|flit)\.dependencies\]|^\[project\]|^\[project\.optional-dependencies\.'
)


def _extract_pypi_deps(diff_content: str, filepath: str = "pyproject.toml") -> list[NewDependency]:
    """Extract newly added PyPI dependencies from pyproject.toml/setup.cfg/requirements diffs."""
    deps: list[NewDependency] = []
    is_dev = False
    line_number = 0

    for raw in diff_content.splitlines():
        line_number += 1

        # Track section context
        stripped = raw.lstrip("+ ")
        if stripped.startswith("["):
            is_dev = "dev" in stripped.lower() or "test" in stripped.lower()
            continue

        if not raw.startswith("+") or raw.startswith("+++"):
            continue

        line = raw[1:].strip()
        # Skip comments, blank lines, section headers
        if not line or line.startswith("#") or line.startswith("["):
            continue

        # pyproject.toml dependencies = ["requests>=2.0", ...]
        # requirements.txt: requests>=2.0
        m = _PYPI_DEP_RE.match(line.strip('"').strip("'"))
        if m:
            name = m.group("name")
            version = (m.group("version") or "").strip().strip('"').strip("'").strip(",")
            if name and not name.startswith("-") and len(name) > 1:
                deps.append(NewDependency(
                    name=name,
                    version_spec=version,
                    ecosystem="pypi",
                    manifest_file=filepath,
                    is_dev=is_dev,
                    line_number=line_number,
                ))

    return deps


# ─── Unified extractor ─────────────────────────────────────────────────────

def extract_new_dependencies(diff_content: str, filepath: str = "") -> list[NewDependency]:
    """
    Extract newly added dependencies from a manifest file diff.

    Supports:
    - package.json (npm)
    - pyproject.toml / setup.cfg / requirements.txt (PyPI)
    """
    fname = filepath.lower()

    if "package.json" in fname:
        return _extract_npm_deps(diff_content, filepath)

    if any(fname.endswith(ext) for ext in (".toml", ".cfg", ".txt", "requirements")):
        return _extract_pypi_deps(diff_content, filepath)

    # Try both if unknown
    npm = _extract_npm_deps(diff_content, filepath)
    pypi = _extract_pypi_deps(diff_content, filepath)
    return npm + pypi


def deps_to_watchlist_entries(deps: list[NewDependency]) -> list[tuple[str, str]]:
    """
    Convert NewDependency list to (name, ecosystem) tuples for watchlist addition.
    Filters out dev dependencies and well-known safe packages.
    """
    # Popular well-known packages that don't need extra scanning
    KNOWN_SAFE = frozenset({
        "lodash", "express", "react", "vue", "angular", "typescript",
        "webpack", "babel", "eslint", "prettier", "jest",
        "requests", "flask", "django", "numpy", "pandas",
        "pytest", "setuptools", "wheel", "pip",
        "follow-redirects", "proxy-from-env",  # axios legit deps
    })

    results = []
    for dep in deps:
        if dep.is_dev:
            continue
        if dep.name.lower() in KNOWN_SAFE:
            continue
        if len(dep.name) < 2:
            continue
        results.append((dep.name, dep.ecosystem))
    return results
