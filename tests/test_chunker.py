"""Tests for DiffChunker."""

import pytest
from depvet.differ.chunker import DiffChunker, DiffFile, DiffChunk


def make_file(path: str, content: str = "x" * 100, binary: bool = False) -> DiffFile:
    return DiffFile(path=path, content=content, is_binary=binary)


def test_empty_input():
    chunker = DiffChunker(max_tokens=1000)
    result = chunker.chunk([])
    assert result == []


def test_single_file():
    chunker = DiffChunker(max_tokens=1000)
    files = [make_file("setup.py", "x" * 100)]
    chunks = chunker.chunk(files)
    assert len(chunks) == 1
    assert chunks[0].files[0].path == "setup.py"


def test_skips_test_files():
    chunker = DiffChunker(max_tokens=1000)
    files = [
        make_file("auth.py"),
        make_file("test_auth.py"),
        make_file("auth_test.py"),
    ]
    chunks = chunker.chunk(files)
    assert len(chunks) == 1
    paths = [f.path for f in chunks[0].files]
    assert "auth.py" in paths
    assert "test_auth.py" not in paths
    assert "auth_test.py" not in paths


def test_priority_files_come_first():
    chunker = DiffChunker(max_tokens=100000)
    files = [
        make_file("utils.py"),
        make_file("setup.py"),
        make_file("helper.py"),
        make_file("__init__.py"),
    ]
    chunks = chunker.chunk(files)
    assert len(chunks) == 1
    paths = [f.path for f in chunks[0].files]
    # setup.py and __init__.py should be before utils.py and helper.py
    assert paths.index("setup.py") < paths.index("utils.py")


def test_chunking_by_token_limit():
    # Each file has 1000 chars = ~250 tokens; limit = 300 tokens → each chunk ~1 file
    chunker = DiffChunker(max_tokens=300)
    files = [make_file(f"file{i}.py", "x" * 1000) for i in range(5)]
    chunks = chunker.chunk(files)
    # Should be split into multiple chunks
    assert len(chunks) > 1


def test_always_at_least_one_file_per_chunk():
    # Even if a single file exceeds max_tokens, it should still be placed in a chunk
    chunker = DiffChunker(max_tokens=10)  # Very small limit
    files = [make_file("huge.py", "x" * 10000)]
    chunks = chunker.chunk(files)
    assert len(chunks) == 1
    assert len(chunks[0].files) == 1


def test_binary_files_included():
    chunker = DiffChunker(max_tokens=10000)
    files = [
        make_file("image.png", binary=True),
        make_file("setup.py"),
    ]
    chunks = chunker.chunk(files)
    assert len(chunks) == 1
    paths = [f.path for f in chunks[0].files]
    assert "image.png" in paths


def test_chunk_content():
    chunker = DiffChunker(max_tokens=10000)
    files = [make_file("auth.py", "def login(): pass")]
    chunks = chunker.chunk(files)
    assert "auth.py" in chunks[0].content
    assert "def login(): pass" in chunks[0].content
