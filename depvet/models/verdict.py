from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class VerdictType(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class FindingCategory(str, Enum):
    OBFUSCATION = "OBFUSCATION"
    NETWORK = "NETWORK"
    PERSISTENCE = "PERSISTENCE"
    EXFILTRATION = "EXFILTRATION"
    EXECUTION = "EXECUTION"
    STEGANOGRAPHY = "STEGANOGRAPHY"
    TYPOSQUATTING = "TYPOSQUATTING"
    DEPENDENCY_CONFUSION = "DEPENDENCY_CONFUSION"
    BUILD_HOOK_ABUSE = "BUILD_HOOK_ABUSE"
    METADATA_MANIPULATION = "METADATA_MANIPULATION"


@dataclass
class Finding:
    category: FindingCategory
    description: str
    file: str
    line_start: Optional[int]
    line_end: Optional[int]
    evidence: str
    cwe: Optional[str]
    severity: Severity


@dataclass
class DiffStats:
    files_changed: int
    lines_added: int
    lines_removed: int
    binary_files: list[str] = field(default_factory=list)
    new_files: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)


@dataclass
class Verdict:
    verdict: VerdictType
    severity: Severity
    confidence: float
    findings: list[Finding]
    summary: str
    analysis_duration_ms: int
    diff_stats: DiffStats
    model: str
    analyzed_at: str
    chunks_analyzed: int
    tokens_used: int
