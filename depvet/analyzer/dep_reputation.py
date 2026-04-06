"""
Dependency reputation evaluator.

For every newly-added dependency detected by dep_extractor, this module
queries the package registry to evaluate its trustworthiness.

The key insight from the axios 2026-03-30 attack:
  - plain-crypto-js@4.2.1 was published just 18 hours before it was injected
  - It had near-zero downloads
  - It had no prior release history

These signals catch UNKNOWN malicious deps that aren't yet in any Known-bad DB.

Evaluated signals:
  AGE_TOO_YOUNG     - Package published less than N days ago
  LOW_DOWNLOADS     - Package has suspiciously few downloads
  SINGLE_VERSION    - Only one version ever published (brand new / purpose-built)
  DOWNLOAD_RATIO    - Parent has 100M DL/week, new dep has 0: massive mismatch
  UNKNOWN_MAINTAINER - Maintainer account is also brand new

Design principle:
  No single signal is a smoking gun. We combine them:
  - AGE < 7 days alone → HIGH
  - AGE < 7 days + SINGLE_VERSION → CRITICAL
  - AGE < 7 days + SINGLE_VERSION + LOW_DOWNLOADS → CRITICAL (very high conf)
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)

# ─── Thresholds ─────────────────────────────────────────────────────────────

# Age thresholds (days since first publish)
AGE_CRITICAL_DAYS = 7  # Published within a week → CRITICAL
AGE_HIGH_DAYS = 30  # Published within a month → HIGH
AGE_MEDIUM_DAYS = 90  # Published within 3 months → MEDIUM

# Weekly download thresholds (absolute)
DOWNLOADS_HIGH_THRESHOLD = 100  # < 100/week → HIGH flag
DOWNLOADS_MEDIUM_THRESHOLD = 1_000  # < 1000/week → MEDIUM flag

# Download ratio: if parent_downloads > X * dep_downloads → suspicious
# e.g. axios (100M/week) vs plain-crypto-js (0/week) → ratio = ∞
DOWNLOAD_RATIO_HIGH = 10_000  # parent 10k× more popular than new dep → HIGH
DOWNLOAD_RATIO_MEDIUM = 1_000  # parent 1k× more popular → MEDIUM


@dataclass
class DepReputationResult:
    """Reputation assessment for a newly-added dependency."""

    package_name: str
    ecosystem: str
    version_spec: str

    # Raw metrics (None = could not be fetched)
    age_days: Optional[int] = None  # Days since first publish
    weekly_downloads: Optional[int] = None  # Last-week downloads
    total_versions: Optional[int] = None  # Total number of published versions
    first_published: Optional[str] = None  # ISO 8601
    latest_version: Optional[str] = None

    # Assessment
    severity: str = "NONE"  # CRITICAL / HIGH / MEDIUM / LOW / NONE
    signals: list[str] = field(default_factory=list)
    confidence_boost: float = 0.0
    description: str = ""

    @property
    def is_suspicious(self) -> bool:
        return self.severity in ("CRITICAL", "HIGH", "MEDIUM")


# ─── Registry fetchers ───────────────────────────────────────────────────────


async def _fetch_npm_metadata(name: str, session: aiohttp.ClientSession) -> Optional[dict]:
    """Fetch npm registry metadata for a package."""
    encoded = name.replace("/", "%2F")
    url = f"https://registry.npmjs.org/{encoded}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 404:
                return None
            if resp.status != 200:
                logger.debug(f"npm registry returned {resp.status} for {name}")
                return None
            return await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.debug(f"Failed to fetch npm metadata for {name}: {e}")
        return None


async def _fetch_npm_downloads(name: str, session: aiohttp.ClientSession) -> Optional[int]:
    """Fetch last-week npm download count."""
    encoded = name.replace("/", "%2F")
    url = f"https://api.npmjs.org/downloads/point/last-week/{encoded}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            if resp.status != 200:
                return None
            data = await resp.json(content_type=None)
            return data.get("downloads", 0)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.debug(f"Failed to fetch npm downloads for {name}: {e}")
        return None


async def _fetch_pypi_metadata(name: str, session: aiohttp.ClientSession) -> Optional[dict]:
    """Fetch PyPI package metadata."""
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 404:
                return None
            if resp.status != 200:
                logger.debug(f"PyPI returned {resp.status} for {name}")
                return None
            return await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.debug(f"Failed to fetch PyPI metadata for {name}: {e}")
        return None


# ─── Reputation evaluators ───────────────────────────────────────────────────


def _days_since(iso_ts: str) -> Optional[int]:
    """Return number of days since an ISO 8601 timestamp."""
    try:
        ts = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - ts).days
    except (ValueError, TypeError):
        return None


def _assess_signals(
    age_days: Optional[int],
    weekly_downloads: Optional[int],
    total_versions: Optional[int],
    parent_downloads: Optional[int] = None,
) -> tuple[str, list[str], float]:
    """
    Assess reputation signals and return (severity, signals, confidence_boost).

    Combination rules (most severe wins):
    - CRITICAL: age < 7d AND (single version OR downloads < 100)
    - HIGH: age < 7d, OR (single version AND downloads < 100)
    - MEDIUM: age < 30d, OR downloads < 1000
    """
    signals: list[str] = []
    score = 0  # accumulate risk score

    # Age signal
    if age_days is not None:
        if age_days < AGE_CRITICAL_DAYS:
            signals.append(f"パッケージ公開から{age_days}日しか経っていない（{AGE_CRITICAL_DAYS}日未満）")
            score += 40
        elif age_days < AGE_HIGH_DAYS:
            signals.append(f"パッケージ公開から{age_days}日（{AGE_HIGH_DAYS}日未満）")
            score += 25
        elif age_days < AGE_MEDIUM_DAYS:
            signals.append(f"パッケージ公開から{age_days}日（{AGE_MEDIUM_DAYS}日未満）")
            score += 10

    # Download signal
    if weekly_downloads is not None:
        if weekly_downloads < DOWNLOADS_HIGH_THRESHOLD:
            signals.append(f"週間DL数がわずか{weekly_downloads}件（{DOWNLOADS_HIGH_THRESHOLD}未満）")
            score += 30
        elif weekly_downloads < DOWNLOADS_MEDIUM_THRESHOLD:
            signals.append(f"週間DL数が{weekly_downloads}件（{DOWNLOADS_MEDIUM_THRESHOLD}未満）")
            score += 15

    # Single version signal (purpose-built package)
    if total_versions is not None and total_versions == 1:
        signals.append("バージョンが1つのみ（攻撃専用パッケージの典型パターン）")
        score += 20

    # Download ratio signal (parent vs dependency)
    if parent_downloads and weekly_downloads is not None and weekly_downloads > 0:
        ratio = parent_downloads / weekly_downloads
        if ratio > DOWNLOAD_RATIO_HIGH:
            signals.append(
                f"親パッケージとの週間DL比が{ratio:.0f}:1（本体は{parent_downloads:,}、依存は{weekly_downloads}）"
            )
            score += 35
        elif ratio > DOWNLOAD_RATIO_MEDIUM:
            signals.append(f"親パッケージとの週間DL比が{ratio:.0f}:1")
            score += 20
    elif parent_downloads and weekly_downloads == 0:
        signals.append(f"ダウンロード実績ゼロのパッケージ（親パッケージは{parent_downloads:,}DL/週）")
        score += 40

    # Determine severity from score
    if score >= 60:
        severity = "CRITICAL"
        confidence_boost = 0.30
    elif score >= 35:
        severity = "HIGH"
        confidence_boost = 0.20
    elif score >= 15:
        severity = "MEDIUM"
        confidence_boost = 0.10
    elif score > 0:
        severity = "LOW"
        confidence_boost = 0.05
    else:
        severity = "NONE"
        confidence_boost = 0.0

    return severity, signals, confidence_boost


async def evaluate_npm_reputation(
    name: str,
    version_spec: str,
    parent_downloads: Optional[int] = None,
) -> DepReputationResult:
    """Evaluate npm package reputation."""
    result = DepReputationResult(package_name=name, ecosystem="npm", version_spec=version_spec)

    async with aiohttp.ClientSession() as session:
        # Fetch metadata and downloads in parallel
        import asyncio

        meta_task = asyncio.create_task(_fetch_npm_metadata(name, session))
        dl_task = asyncio.create_task(_fetch_npm_downloads(name, session))
        meta, downloads = await asyncio.gather(meta_task, dl_task, return_exceptions=True)

    if isinstance(meta, Exception) or meta is None:
        result.description = f"メタデータ取得失敗（{name}はレジストリに存在しない可能性）"
        result.severity = "HIGH"
        result.signals = ["npmレジストリにパッケージが存在しないか取得できない"]
        result.confidence_boost = 0.15
        return result

    if isinstance(downloads, Exception):
        downloads = None

    # Parse metadata
    time_data = meta.get("time", {})
    created_at = time_data.get("created", "")
    age_days = _days_since(created_at) if created_at else None

    versions = meta.get("versions", {})
    total_versions = len(versions)

    dist_tags = meta.get("dist-tags", {})
    latest = dist_tags.get("latest", "")

    result.age_days = age_days
    result.weekly_downloads = downloads if isinstance(downloads, int) else None
    result.total_versions = total_versions
    result.first_published = created_at
    result.latest_version = latest

    severity, signals, confidence_boost = _assess_signals(
        age_days=age_days,
        weekly_downloads=result.weekly_downloads,
        total_versions=total_versions,
        parent_downloads=parent_downloads,
    )

    result.severity = severity
    result.signals = signals
    result.confidence_boost = confidence_boost
    result.description = _build_description(name, "npm", severity, signals, age_days, result.weekly_downloads)
    return result


async def evaluate_pypi_reputation(
    name: str,
    version_spec: str,
    parent_downloads: Optional[int] = None,
) -> DepReputationResult:
    """Evaluate PyPI package reputation."""
    result = DepReputationResult(package_name=name, ecosystem="pypi", version_spec=version_spec)

    async with aiohttp.ClientSession() as session:
        meta = await _fetch_pypi_metadata(name, session)

    if meta is None:
        result.description = f"PyPIにパッケージが存在しない ({name})"
        result.severity = "HIGH"
        result.signals = ["PyPIレジストリにパッケージが存在しない"]
        result.confidence_boost = 0.15
        return result

    info = meta.get("info", {})
    releases = meta.get("releases", {})
    total_versions = len(releases)

    # Get creation date from first release
    first_published = None
    age_days = None
    for version_files in releases.values():
        for f in version_files:
            ts = f.get("upload_time_iso_8601", "")
            if ts:
                if first_published is None or ts < first_published:
                    first_published = ts
    if first_published:
        age_days = _days_since(first_published)

    # PyPI doesn't have a direct downloads API (BigQuery only), use None
    weekly_downloads = None

    result.age_days = age_days
    result.weekly_downloads = weekly_downloads
    result.total_versions = total_versions
    result.first_published = first_published
    result.latest_version = info.get("version", "")

    severity, signals, confidence_boost = _assess_signals(
        age_days=age_days,
        weekly_downloads=weekly_downloads,
        total_versions=total_versions,
        parent_downloads=parent_downloads,
    )

    result.severity = severity
    result.signals = signals
    result.confidence_boost = confidence_boost
    result.description = _build_description(name, "pypi", severity, signals, age_days, weekly_downloads)
    return result


async def evaluate_dep_reputation(
    name: str,
    ecosystem: str,
    version_spec: str,
    parent_downloads: Optional[int] = None,
) -> DepReputationResult:
    """Unified reputation evaluator."""
    if ecosystem == "npm":
        return await evaluate_npm_reputation(name, version_spec, parent_downloads)
    elif ecosystem == "pypi":
        return await evaluate_pypi_reputation(name, version_spec, parent_downloads)
    else:
        # Go/Cargo/Maven: return MEDIUM for unknown ecosystems (conservative)
        return DepReputationResult(
            package_name=name,
            ecosystem=ecosystem,
            version_spec=version_spec,
            severity="NONE",
            description="",
        )


def _build_description(
    name: str,
    ecosystem: str,
    severity: str,
    signals: list[str],
    age_days: Optional[int],
    weekly_downloads: Optional[int],
) -> str:
    if not signals:
        return ""
    icon = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "🔶"}.get(severity, "")
    parts = [f"{icon} 新規依存パッケージ '{name}' の信頼性評価: {severity}"]
    for s in signals:
        parts.append(f"  • {s}")
    return "\n".join(parts)
