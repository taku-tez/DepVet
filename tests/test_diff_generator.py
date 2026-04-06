"""Tests for diff generator."""

import tempfile
from pathlib import Path


from depvet.differ.diff_generator import generate_diff, format_diff_markdown


def _create_package(tmpdir: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        p = tmpdir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmpdir


def test_diff_identical():
    with tempfile.TemporaryDirectory() as td:
        old = _create_package(Path(td) / "old", {"main.py": "print('hello')\n"})
        new = _create_package(Path(td) / "new", {"main.py": "print('hello')\n"})
        chunks, stats = generate_diff(old, new)
        assert stats.files_changed == 0
        assert stats.lines_added == 0


def test_diff_modified_file():
    with tempfile.TemporaryDirectory() as td:
        old = _create_package(Path(td) / "old", {"main.py": "print('hello')\n"})
        new = _create_package(Path(td) / "new", {"main.py": "print('world')\n"})
        chunks, stats = generate_diff(old, new)
        assert stats.files_changed == 1
        assert stats.lines_added >= 1
        assert stats.lines_removed >= 1


def test_diff_new_file():
    with tempfile.TemporaryDirectory() as td:
        old = _create_package(Path(td) / "old", {"main.py": "pass\n"})
        new = _create_package(Path(td) / "new", {"main.py": "pass\n", "evil.py": "exec('rm -rf /')\n"})
        chunks, stats = generate_diff(old, new)
        assert "evil.py" in stats.new_files


def test_diff_deleted_file():
    with tempfile.TemporaryDirectory() as td:
        old = _create_package(Path(td) / "old", {"main.py": "pass\n", "old.py": "legacy\n"})
        new = _create_package(Path(td) / "new", {"main.py": "pass\n"})
        chunks, stats = generate_diff(old, new)
        assert "old.py" in stats.deleted_files


def test_diff_skip_test_files():
    with tempfile.TemporaryDirectory() as td:
        old = _create_package(
            Path(td) / "old",
            {
                "main.py": "pass\n",
                "test_main.py": "pass\n",
            },
        )
        new = _create_package(
            Path(td) / "new",
            {
                "main.py": "changed\n",
                "test_main.py": "changed tests\n",
            },
        )
        chunks, stats = generate_diff(old, new)
        # Chunks should NOT contain test files
        all_paths = [f.path for chunk in chunks for f in chunk.files]
        assert "test_main.py" not in all_paths
        assert "main.py" in all_paths


def test_format_diff_markdown():
    with tempfile.TemporaryDirectory() as td:
        old = _create_package(Path(td) / "old", {"main.py": "old\n"})
        new = _create_package(Path(td) / "new", {"main.py": "new\n"})
        chunks, stats = generate_diff(old, new)
        md = format_diff_markdown(chunks, stats)
        assert "# Package Diff" in md
        assert "Files changed:" in md
