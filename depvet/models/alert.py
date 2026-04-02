from dataclasses import dataclass, field

from depvet.models.package import Release
from depvet.models.verdict import Verdict


@dataclass
class AlertEvent:
    release: Release
    verdict: Verdict
    affected_tenants: list[str] = field(default_factory=list)
