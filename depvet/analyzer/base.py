"""Abstract base class for LLM analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from depvet.differ.chunker import DiffChunk
from depvet.models.verdict import Verdict


class BaseAnalyzer(ABC):
    """Abstract LLM analyzer interface."""

    @abstractmethod
    async def triage(
        self,
        chunk: DiffChunk,
        package_name: str,
        old_version: str,
        new_version: str,
    ) -> tuple[bool, str]:
        """
        Stage 1: Quick triage. Returns (should_analyze, reason).
        """
        ...

    @abstractmethod
    async def deep_analyze(
        self,
        chunk: DiffChunk,
        chunk_index: int,
        total_chunks: int,
        package_name: str,
        old_version: str,
        new_version: str,
        ecosystem: str,
    ) -> dict:
        """
        Stage 2: Deep analysis. Returns raw dict matching Verdict schema.
        """
        ...

    @abstractmethod
    def get_model_name(self) -> str:
        """Return the model name/identifier being used."""
        ...
