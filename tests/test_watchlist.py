"""Tests for watchlist management."""

import json
import os
import tempfile

from depvet.watchlist.explicit import ExplicitSource
from depvet.watchlist.manager import WatchlistManager
from depvet.watchlist.sbom import SBOMParser, _parse_purl


# ─── ExplicitSource ───────────────────────────────────────────


def test_explicit_add_and_list():
    src = ExplicitSource()
    src.add("requests", "pypi")
    src.add("axios", "npm")
    entries = src.entries()
    assert len(entries) == 2


def test_explicit_no_duplicates():
    src = ExplicitSource()
    src.add("requests", "pypi")
    src.add("requests", "pypi")
    assert len(src.entries()) == 1


def test_explicit_remove():
    src = ExplicitSource()
    src.add("requests", "pypi")
    removed = src.remove("requests", "pypi")
    assert removed is True
    assert len(src.entries()) == 0


def test_explicit_remove_not_found():
    src = ExplicitSource()
    removed = src.remove("nonexistent", "pypi")
    assert removed is False


def test_explicit_as_set():
    src = ExplicitSource()
    src.add("requests", "pypi")
    src.add("flask", "pypi")
    src.add("axios", "npm")
    pypi = src.as_set("pypi")
    assert pypi == {"requests", "flask"}


def test_explicit_load_from_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("requests\nflask\n# comment\n\nnumpy\n")
        path = f.name
    try:
        src = ExplicitSource()
        count = src.load_from_file(path, "pypi")
        assert count == 3
        assert "requests" in src.as_set("pypi")
        assert "numpy" in src.as_set("pypi")
    finally:
        os.unlink(path)


# ─── SBOM Parser ──────────────────────────────────────────────


def test_parse_purl_pypi():
    entry = _parse_purl("pkg:pypi/requests@2.31.0")
    assert entry is not None
    assert entry.name == "requests"
    assert entry.ecosystem == "pypi"
    assert entry.current_version == "2.31.0"


def test_parse_purl_npm():
    entry = _parse_purl("pkg:npm/axios@1.6.0")
    assert entry is not None
    assert entry.name == "axios"
    assert entry.ecosystem == "npm"


def test_parse_purl_npm_scoped():
    entry = _parse_purl("pkg:npm/%40babel/core@7.0.0")
    # Even without proper URL decoding, should not crash
    assert entry is not None


def test_parse_purl_invalid():
    entry = _parse_purl("not-a-purl")
    assert entry is None


def test_sbom_parser_cyclonedx_json():
    sbom_data = {
        "bomFormat": "CycloneDX",
        "components": [
            {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
            {"type": "library", "name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"},
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(sbom_data, f)
        path = f.name
    try:
        parser = SBOMParser()
        entries = parser.parse(path)
        names = [e.name for e in entries]
        assert "requests" in names
        assert "flask" in names
    finally:
        os.unlink(path)


# ─── WatchlistManager ─────────────────────────────────────────


def test_watchlist_manager_add_remove():
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    try:
        os.unlink(path)  # Remove so manager starts fresh
        wl = WatchlistManager(storage_path=path)
        wl.add("requests", "pypi")
        wl.add("flask", "pypi")

        wl2 = WatchlistManager(storage_path=path)  # reload
        assert "requests" in wl2.as_set("pypi")

        wl2.remove("requests", "pypi")
        assert "requests" not in wl2.as_set("pypi")
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_watchlist_stats():
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        path = f.name
    try:
        os.unlink(path)
        wl = WatchlistManager(storage_path=path)
        wl.add("requests", "pypi")
        wl.add("flask", "pypi")
        wl.add("axios", "npm")

        stats = wl.stats()
        assert stats["total"] == 3
        assert stats["by_ecosystem"]["pypi"] == 2
        assert stats["by_ecosystem"]["npm"] == 1
    finally:
        if os.path.exists(path):
            os.unlink(path)
