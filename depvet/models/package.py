from dataclasses import dataclass
from typing import Optional


@dataclass
class Release:
    name: str
    version: str
    ecosystem: str  # "pypi" or "npm"
    previous_version: Optional[str]
    published_at: str
    url: str
    rank: Optional[int] = None
