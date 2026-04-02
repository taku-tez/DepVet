"""Diff chunker for LLM token management."""

from __future__ import annotations

from dataclasses import dataclass, field

from depvet.differ.priority import priority_sort_key, should_skip


@dataclass
class DiffFile:
    """A single file's diff."""
    path: str
    content: str
    is_binary: bool = False
    is_new: bool = False
    is_deleted: bool = False


@dataclass
class DiffChunk:
    """A chunk of diff files for LLM analysis."""
    chunk_index: int
    total_files: int
    files: list[DiffFile] = field(default_factory=list)
    token_count: int = 0

    def add_file(self, diff_file: DiffFile, tokens: int) -> None:
        self.files.append(diff_file)
        self.token_count += tokens

    @property
    def content(self) -> str:
        parts = []
        for f in self.files:
            if f.is_binary:
                parts.append(f"[Binary file: {f.path}]")
            else:
                parts.append(f"--- {f.path}\n{f.content}")
        return "\n\n".join(parts)


class DiffChunker:
    """
    Splits large diffs into chunks that fit within LLM context windows.

    Strategy:
    1. Place priority files in the first chunk
    2. Keep each chunk within MAX_TOKENS
    3. Only split at file boundaries (preserve code context)
    4. Skip test/doc files
    """

    MAX_TOKENS_PER_CHUNK = 8_000
    CHARS_PER_TOKEN = 4  # rough estimate

    def __init__(self, max_tokens: int = MAX_TOKENS_PER_CHUNK):
        self.max_tokens = max_tokens

    def _estimate_tokens(self, text: str) -> int:
        return max(1, len(text) // self.CHARS_PER_TOKEN)

    def chunk(self, diff_files: list[DiffFile]) -> list[DiffChunk]:
        """Split diff files into token-sized chunks."""
        # Filter skip patterns
        filtered = [f for f in diff_files if not should_skip(f.path)]

        # Sort: priority files first
        sorted_files = sorted(filtered, key=lambda f: priority_sort_key(f.path))

        if not sorted_files:
            return []

        chunks: list[DiffChunk] = []
        current = DiffChunk(chunk_index=0, total_files=len(sorted_files))

        for diff_file in sorted_files:
            if diff_file.is_binary:
                content_for_tokens = f"[Binary file: {diff_file.path}]"
            else:
                content_for_tokens = diff_file.content

            file_tokens = self._estimate_tokens(content_for_tokens)

            # If adding this file would exceed the limit, start a new chunk
            # (unless the current chunk is empty — we always add at least one file)
            if current.files and current.token_count + file_tokens > self.max_tokens:
                chunks.append(current)
                current = DiffChunk(
                    chunk_index=len(chunks),
                    total_files=len(sorted_files),
                )

            current.add_file(diff_file, file_tokens)

        if current.files:
            chunks.append(current)

        # Update total_chunks on each chunk now that we know the total
        total = len(chunks)
        for i, chunk in enumerate(chunks):
            chunk.chunk_index = i
            # Attach total as attribute for convenience
            object.__setattr__(chunk, "_total_chunks", total) if False else None

        return chunks

    @property
    def total_chunks_attr(self) -> str:
        return "_total_chunks"
