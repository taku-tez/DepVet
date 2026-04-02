"""Abstract base class for package registry watchers."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import AsyncIterator
from depvet.models.package import Release


class BaseRegistry(ABC):
    @abstractmethod
    async def poll(self) -> list[Release]:
        """Poll for new releases since last check. Returns list of Release."""
        ...

    @abstractmethod
    async def get_versions(self, package_name: str) -> list[str]:
        """Get all versions of a package."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Clean up resources."""
        ...
