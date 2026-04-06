"""Tests for known-bad database."""

import os
import tempfile
from pathlib import Path

from depvet.known_bad.database import KnownBadDB, KnownBadEntry


def test_bundled_db_loads():
    db = KnownBadDB()
    assert db.count() > 0


def test_lookup_known_bad():
    db = KnownBadDB()
    hit = db.lookup("ctx", "0.2.1", "pypi")
    assert hit is not None
    assert hit.verdict == "MALICIOUS"
    assert hit.severity == "CRITICAL"


def test_lookup_clean():
    db = KnownBadDB()
    hit = db.lookup("requests", "2.31.0", "pypi")
    assert hit is None


def test_add_entry():
    db = KnownBadDB()
    initial = db.count()
    db.add(
        KnownBadEntry(
            name="evil-pkg",
            version="1.0.0",
            ecosystem="pypi",
            verdict="MALICIOUS",
            severity="HIGH",
            summary="Test entry",
            source="manual",
            reported_at="2026-01-01",
        )
    )
    assert db.count() == initial + 1
    assert db.lookup("evil-pkg", "1.0.0", "pypi") is not None


def test_no_duplicate_add():
    db = KnownBadDB()
    db.add(
        KnownBadEntry(
            name="test-dup",
            version="1.0.0",
            ecosystem="npm",
            verdict="SUSPICIOUS",
            severity="MEDIUM",
            summary="Dup test",
            source="manual",
            reported_at="2026-01-01",
        )
    )
    count1 = db.count()
    db.add(
        KnownBadEntry(
            name="test-dup",
            version="1.0.0",
            ecosystem="npm",
            verdict="SUSPICIOUS",
            severity="MEDIUM",
            summary="Dup test",
            source="manual",
            reported_at="2026-01-01",
        )
    )
    assert db.count() == count1


def test_save_and_reload():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)

    try:
        db = KnownBadDB(db_path=path)
        db.add(
            KnownBadEntry(
                name="test-save",
                version="2.0.0",
                ecosystem="pypi",
                verdict="MALICIOUS",
                severity="CRITICAL",
                summary="Save test",
                source="manual",
                reported_at="2026-04-01",
            )
        )
        db.save(path)

        db2 = KnownBadDB(db_path=path)
        assert db2.count() == 1
        assert db2.lookup("test-save", "2.0.0", "pypi") is not None
    finally:
        os.unlink(path)


def test_empty_db():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    os.unlink(path)

    db = KnownBadDB(db_path=path)
    assert db.count() == 0
    assert db.lookup("anything", "1.0.0", "pypi") is None
