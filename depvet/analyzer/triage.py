"""Stage 1: Triage analysis pipeline."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from depvet.analyzer.base import BaseAnalyzer
from depvet.differ.chunker import DiffChunk

logger = logging.getLogger(__name__)


class TriageAnalyzer:
    """
    Stage 1: Quick triage of diff chunks.
    Determines whether a chunk needs deep analysis.
    """

    def __init__(self, analyzer: BaseAnalyzer):
        self.analyzer = analyzer

    async def should_analyze(
        self,
        chunks: list[DiffChunk],
        package_name: str,
        old_version: str,
        new_version: str,
    ) -> tuple[bool, str]:
        """
        Run triage on first chunk (or all chunks in parallel for accuracy).
        Returns (should_deep_analyze, reason).
        """
        if not chunks:
            return False, "no diff chunks"

        # Triage the first chunk (usually priority files); if it says analyze, we do
        should, reason = await self.analyzer.triage(
            chunks[0], package_name, old_version, new_version
        )
        if should:
            return True, reason

        # If first chunk says skip but there are more chunks with binary/new files, still analyze
        for chunk in chunks[1:]:
            for f in chunk.files:
                if f.is_binary or f.is_new:
                    return True, f"binary or new file in chunk {chunk.chunk_index}"

        return False, reason
