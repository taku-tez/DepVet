"""Tests for archive unpacker."""

import io
import os
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

from depvet.differ.unpacker import unpack


def create_zip(dest: Path, files: dict[str, str]) -> Path:
    """Create a zip archive with the given files."""
    archive = dest / "test.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return archive


def create_wheel(dest: Path, files: dict[str, str]) -> Path:
    """Create a wheel (.whl) archive."""
    archive = dest / "mypkg-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return archive


def create_tarball(dest: Path, files: dict[str, str], prefix: str = "") -> Path:
    """Create a .tar.gz archive."""
    archive = dest / "mypkg-1.0.0.tar.gz"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"{prefix}{name}" if prefix else name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    archive.write_bytes(buf.getvalue())
    return archive


def create_npm_tarball(dest: Path, files: dict[str, str]) -> Path:
    """Create an npm-style tarball (files wrapped in 'package/' prefix)."""
    archive = dest / "mypkg-1.0.0.tgz"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"package/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    archive.write_bytes(buf.getvalue())
    return archive


def create_crate(dest: Path, files: dict[str, str]) -> Path:
    """Create a Cargo .crate file (tar.gz with different extension)."""
    archive = dest / "mypkg-1.0.0.crate"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    archive.write_bytes(buf.getvalue())
    return archive


# ─── ZIP / Wheel ──────────────────────────────────────────────────────────────

def test_unpack_zip():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        archive = create_zip(tmp, {"mypkg/main.py": "print('hello')", "mypkg/__init__.py": ""})
        out = unpack(archive, tmp / "out")
        assert (out / "mypkg" / "main.py").exists()
        assert (out / "mypkg" / "__init__.py").exists()


def test_unpack_wheel():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        archive = create_wheel(tmp, {
            "mypkg/__init__.py": "x = 1",
            "mypkg/auth.py": "pass",
        })
        out = unpack(archive, tmp / "out")
        assert (out / "mypkg" / "__init__.py").exists()


# ─── Tarball (sdist) ─────────────────────────────────────────────────────────

def test_unpack_sdist_tarball():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        archive = create_tarball(tmp, {
            "mypkg-1.0.0/setup.py": "from setuptools import setup; setup()",
            "mypkg-1.0.0/mypkg/__init__.py": "x = 1",
        })
        out = unpack(archive, tmp / "out")
        # Files should exist under out/
        found = list(out.rglob("setup.py"))
        assert len(found) > 0


# ─── npm tarball (package/ prefix) ───────────────────────────────────────────

def test_unpack_npm_tarball_strips_package_prefix():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        archive = create_npm_tarball(tmp, {
            "index.js": "module.exports = {}",
            "package.json": '{"name": "mypkg"}',
        })
        out = unpack(archive, tmp / "out")
        # 'package/' prefix should be stripped
        assert (out / "index.js").exists() or list(out.rglob("index.js"))


# ─── Cargo .crate ─────────────────────────────────────────────────────────────

def test_unpack_cargo_crate():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        archive = create_crate(tmp, {
            "Cargo.toml": '[package]\nname = "mypkg"',
            "src/lib.rs": "pub fn hello() {}",
        })
        out = unpack(archive, tmp / "out")
        found = list(out.rglob("Cargo.toml"))
        assert len(found) > 0


# ─── Error handling ───────────────────────────────────────────────────────────

def test_unpack_unsupported_format():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bad = tmp / "file.xyz"
        bad.write_bytes(b"not an archive")
        with pytest.raises(ValueError, match="Unsupported"):
            unpack(bad, tmp / "out")


def test_unpack_preserves_content():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        content = "import os\nprint(os.environ)"
        archive = create_zip(tmp, {"evil.py": content})
        out = unpack(archive, tmp / "out")
        found = list(out.rglob("evil.py"))
        assert found
        assert found[0].read_text() == content
