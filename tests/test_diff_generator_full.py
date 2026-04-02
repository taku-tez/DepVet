"""Comprehensive diff_generator tests — binary detection, edge cases, chunking."""

import tempfile
from pathlib import Path

import pytest

from depvet.differ.diff_generator import (
    generate_diff,
    format_diff_markdown,
    _is_binary_file,
    _read_lines,
    _collect_files,
)
from depvet.differ.chunker import DiffChunker


def _create_pkg(base: Path, files: dict[str, bytes | str]) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        p = base / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
    return base


# ─── _is_binary_file ─────────────────────────────────────────────────────────

class TestIsBinaryFile:
    def test_python_file_not_binary(self, tmp_path):
        p = tmp_path / "module.py"
        p.write_text("def hello(): pass\n")
        assert _is_binary_file(p) is False

    def test_so_extension_is_binary(self, tmp_path):
        p = tmp_path / "lib.so"
        p.write_bytes(b"\x7fELF\x02\x01\x01\x00")
        assert _is_binary_file(p) is True

    def test_dll_extension_is_binary(self, tmp_path):
        p = tmp_path / "evil.dll"
        p.write_text("not real dll")
        assert _is_binary_file(p) is True

    def test_null_bytes_detected(self, tmp_path):
        p = tmp_path / "data.bin"
        p.write_bytes(b"hello\x00world")
        assert _is_binary_file(p) is True

    def test_clean_text_not_binary(self, tmp_path):
        p = tmp_path / "readme.txt"
        p.write_text("This is plain text\n" * 100)
        assert _is_binary_file(p) is False

    def test_png_extension_is_binary(self, tmp_path):
        p = tmp_path / "icon.png"
        p.write_bytes(b"\x89PNG\r\n\x1a\n")
        assert _is_binary_file(p) is True


# ─── _read_lines ─────────────────────────────────────────────────────────────

class TestReadLines:
    def test_reads_utf8(self, tmp_path):
        p = tmp_path / "test.py"
        p.write_text("line1\nline2\nline3\n", encoding="utf-8")
        lines = _read_lines(p)
        assert len(lines) == 3
        assert lines[0] == "line1\n"

    def test_handles_missing_file(self, tmp_path):
        p = tmp_path / "nonexistent.py"
        lines = _read_lines(p)
        assert lines == []

    def test_handles_encoding_errors(self, tmp_path):
        p = tmp_path / "bad.py"
        p.write_bytes(b"line1\n\xff\xfe\nline3\n")
        lines = _read_lines(p)
        assert len(lines) >= 1  # should not crash


# ─── _collect_files ──────────────────────────────────────────────────────────

class TestCollectFiles:
    def test_collects_all_files(self, tmp_path):
        (tmp_path / "a.py").write_text("x=1")
        (tmp_path / "sub").mkdir(exist_ok=True)
        (tmp_path / "sub" / "b.py").write_text("y=2")
        files = _collect_files(tmp_path)
        paths = set(files.keys())
        assert "a.py" in paths
        assert str(Path("sub/b.py")) in paths

    def test_empty_directory(self, tmp_path):
        files = _collect_files(tmp_path)
        assert files == {}

    def test_nonexistent_directory(self, tmp_path):
        files = _collect_files(tmp_path / "nonexistent")
        assert files == {}


# ─── generate_diff ────────────────────────────────────────────────────────────

class TestGenerateDiff:
    def test_identical_dirs_no_diff(self, tmp_path):
        old = _create_pkg(tmp_path / "old", {"main.py": "x = 1\n"})
        new = _create_pkg(tmp_path / "new", {"main.py": "x = 1\n"})
        chunks, stats = generate_diff(old, new)
        assert stats.files_changed == 0
        assert stats.lines_added == 0
        assert stats.lines_removed == 0

    def test_modified_file(self, tmp_path):
        old = _create_pkg(tmp_path / "old", {"main.py": "x = 1\n"})
        new = _create_pkg(tmp_path / "new", {"main.py": "x = 2\n"})
        chunks, stats = generate_diff(old, new)
        assert stats.files_changed == 1
        assert stats.lines_added == 1
        assert stats.lines_removed == 1

    def test_new_file_detected(self, tmp_path):
        old = _create_pkg(tmp_path / "old", {"main.py": "pass\n"})
        new = _create_pkg(tmp_path / "new", {"main.py": "pass\n", "extra.py": "evil()\n"})
        chunks, stats = generate_diff(old, new)
        assert "extra.py" in stats.new_files

    def test_deleted_file_detected(self, tmp_path):
        old = _create_pkg(tmp_path / "old", {"main.py": "pass\n", "old.py": "legacy\n"})
        new = _create_pkg(tmp_path / "new", {"main.py": "pass\n"})
        chunks, stats = generate_diff(old, new)
        assert "old.py" in stats.deleted_files

    def test_binary_file_detected(self, tmp_path):
        old = _create_pkg(tmp_path / "old", {"main.py": "pass\n"})
        new = _create_pkg(tmp_path / "new", {"main.py": "pass\n",
                                               "evil.so": b"\x7fELF\x00\x00\x00\x00"})
        chunks, stats = generate_diff(old, new)
        assert "evil.so" in stats.binary_files

    def test_test_files_skipped_from_chunks(self, tmp_path):
        old = _create_pkg(tmp_path / "old", {"pkg.py": "x=1\n", "test_pkg.py": "pass\n"})
        new = _create_pkg(tmp_path / "new", {"pkg.py": "x=2\n", "test_pkg.py": "changed\n"})
        chunks, stats = generate_diff(old, new)
        all_paths = {f.path for chunk in chunks for f in chunk.files}
        assert "test_pkg.py" not in all_paths
        assert "pkg.py" in all_paths

    def test_priority_file_first_in_chunk(self, tmp_path):
        """setup.py should appear before utils.py in chunks."""
        old = _create_pkg(tmp_path / "old", {"setup.py": "old\n", "utils.py": "x=1\n"})
        new = _create_pkg(tmp_path / "new", {"setup.py": "new\n", "utils.py": "x=2\n"})
        chunks, stats = generate_diff(old, new)
        first_chunk_paths = [f.path for f in chunks[0].files]
        assert first_chunk_paths.index("setup.py") < first_chunk_paths.index("utils.py")

    def test_chunking_respects_token_limit(self, tmp_path):
        """Large diffs should be split into multiple chunks."""
        content = "x = 1\n" * 1000  # large file
        old = _create_pkg(tmp_path / "old", {f"file{i}.py": "old\n" for i in range(10)})
        new = _create_pkg(tmp_path / "new", {f"file{i}.py": content for i in range(10)})
        chunks, stats = generate_diff(old, new, max_chunk_tokens=500)
        assert len(chunks) > 1

    def test_empty_old_dir(self, tmp_path):
        old = tmp_path / "old"
        old.mkdir()
        new = _create_pkg(tmp_path / "new", {"main.py": "print('hello')\n"})
        chunks, stats = generate_diff(old, new)
        assert "main.py" in stats.new_files

    def test_empty_new_dir(self, tmp_path):
        old = _create_pkg(tmp_path / "old", {"main.py": "pass\n"})
        new = tmp_path / "new"
        new.mkdir()
        chunks, stats = generate_diff(old, new)
        assert "main.py" in stats.deleted_files

    def test_nested_files(self, tmp_path):
        old = _create_pkg(tmp_path / "old", {"pkg/__init__.py": "v=1\n", "pkg/auth.py": "pass\n"})
        new = _create_pkg(tmp_path / "new", {"pkg/__init__.py": "v=2\n", "pkg/auth.py": "evil\n"})
        chunks, stats = generate_diff(old, new)
        assert stats.files_changed >= 2

    def test_format_diff_markdown_structure(self, tmp_path):
        old = _create_pkg(tmp_path / "old", {"main.py": "old\n"})
        new = _create_pkg(tmp_path / "new", {"main.py": "new\n"})
        chunks, stats = generate_diff(old, new)
        md = format_diff_markdown(chunks, stats)
        assert "# Package Diff" in md
        assert "Files changed:" in md
        assert "Lines added:" in md
        assert "```diff" in md or "Chunk" in md
