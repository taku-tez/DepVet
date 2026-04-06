"""Abstract base class for registry monitors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

import aiohttp

from depvet.models.package import Release


class BaseRegistryMonitor(ABC):
    """Abstract registry monitor interface."""

    @abstractmethod
    async def get_new_releases(
        self,
        watchlist: set[str],
        since_state: dict,
        session: Optional[aiohttp.ClientSession] = None,
    ) -> tuple[list[Release], dict]:
        """
        Fetch new releases for packages in watchlist since the given state.
        Returns: (releases, new_state)
        """
        ...

    @abstractmethod
    async def load_top_n(self, n: int, session: Optional[aiohttp.ClientSession] = None) -> list[str]:
        """Return top N package names by download count."""
        ...

    @property
    @abstractmethod
    def ecosystem(self) -> str:
        """Ecosystem identifier."""
        ...
