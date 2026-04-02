"""
Version transition signals — detects suspicious changes BETWEEN versions.

This is the core differentiator from RepVet (which analyzes a package in isolation).
DepVet asks: "Is this specific update suspicious?"

Signals:
- Maintainer changed since last version (account takeover indicator)
- Long dormancy followed by update (abandoned package revived)
- New install hook added (was not present in old version)
- New suspicious dependency added
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)


# Security-related packages — long dormancy is expected, don't penalize
SECURITY_PACKAGES = frozenset({
    "cryptography", "pyopenssl", "paramiko", "bcrypt", "pyca",
    "pynacl", "cffi", "certifi", "urllib3",
    "openssl", "libsodium", "gnupg",
    # npm
    "helmet", "jsonwebtoken", "bcryptjs", "node-forge",
    "argon2", "tweetnacl", "elliptic",
})

def _is_security_package(name: str) -> bool:
    name_lower = name.lower()
    return (
        name_lower in SECURITY_PACKAGES or
        any(kw in name_lower for kw in ("crypto", "ssl", "tls", "auth", "cipher", "hash", "sign"))
    )


@dataclass
class VersionSignal:
    """A suspicious signal detected in the version transition."""
    signal_id: str
    description: str
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW
    confidence_boost: float  # how much to add to final confidence if SUSPICIOUS/MALICIOUS


@dataclass
class VersionTransitionContext:
    """Context about a package version transition."""
    package_name: str
    ecosystem: str
    old_version: str
    new_version: str
    signals: list[VersionSignal] = field(default_factory=list)
    days_since_last_release: Optional[int] = None
    maintainer_changed: bool = False
    new_install_hook: bool = False
    new_suspicious_deps: list[str] = field(default_factory=list)

    @property
    def has_high_risk_signals(self) -> bool:
        return any(s.severity in ("CRITICAL", "HIGH") for s in self.signals)

    @property
    def total_confidence_boost(self) -> float:
        return sum(s.confidence_boost for s in self.signals)

    def summary(self) -> str:
        if not self.signals:
            return ""
        parts = [s.description for s in self.signals]
        return "【バージョン遷移シグナル】" + " / ".join(parts)


async def analyze_pypi_transition(
    name: str,
    old_version: str,
    new_version: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> VersionTransitionContext:
    """Fetch PyPI metadata and detect suspicious version transition signals."""
    ctx = VersionTransitionContext(
        package_name=name,
        ecosystem="pypi",
        old_version=old_version,
        new_version=new_version,
    )
    close = session is None
    if session is None:
        session = aiohttp.ClientSession()

    try:
        url = f"https://pypi.org/pypi/{name}/json"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                return ctx
            data = await resp.json()
    except Exception as e:
        logger.debug(f"PyPI metadata fetch failed for {name}: {e}")
        return ctx
    finally:
        if close:
            await session.close()

    releases = data.get("releases", {})
    info = data.get("info", {})

    # --- Signal: Dormancy (long gap since last release) ---
    old_files = releases.get(old_version, [])
    new_files = releases.get(new_version, [])

    old_ts = _extract_upload_time(old_files)
    new_ts = _extract_upload_time(new_files)

    if old_ts and new_ts:
        gap_days = (new_ts - old_ts).days
        ctx.days_since_last_release = gap_days
        if gap_days > 365:
            ctx.signals.append(VersionSignal(
                signal_id="LONG_DORMANCY",
                description=f"前回リリースから{gap_days}日ぶりの更新（休眠パッケージの復活）",
                severity="HIGH",
                confidence_boost=0.15,
            ))
        elif gap_days > 180:
            ctx.signals.append(VersionSignal(
                signal_id="MEDIUM_DORMANCY",
                description=f"前回リリースから{gap_days}日ぶりの更新",
                severity="MEDIUM",
                confidence_boost=0.08,
            ))

    # --- Signal: Maintainer change ---
    old_info = await _get_version_info_pypi(name, old_version)
    new_info_author = info.get("author", "")
    if old_info:
        old_author = old_info.get("author", "")
        if old_author and new_info_author and old_author != new_info_author:
            ctx.maintainer_changed = True
            ctx.signals.append(VersionSignal(
                signal_id="MAINTAINER_CHANGE",
                description=f"メンテナーが変更された（{old_author} → {new_info_author}）",
                severity="HIGH",
                confidence_boost=0.20,
            ))

    # --- Signal: New install hook ---
    # Check if setup.py install hook was present in old version's file list
    old_has_setup = any("setup.py" in (f.get("filename", "") or "") for f in old_files)
    new_has_setup = any("setup.py" in (f.get("filename", "") or "") for f in new_files)
    # We detect hook content in diff separately; here just flag setup.py appearance
    if new_has_setup and not old_has_setup:
        ctx.new_install_hook = True
        ctx.signals.append(VersionSignal(
            signal_id="NEW_SETUP_PY",
            description="新バージョンでsetup.pyが追加された（インストール時実行の可能性）",
            severity="MEDIUM",
            confidence_boost=0.10,
        ))

    return ctx


async def analyze_npm_transition(
    name: str,
    old_version: str,
    new_version: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> VersionTransitionContext:
    """Fetch npm metadata and detect suspicious version transition signals."""
    ctx = VersionTransitionContext(
        package_name=name,
        ecosystem="npm",
        old_version=old_version,
        new_version=new_version,
    )
    close = session is None
    if session is None:
        session = aiohttp.ClientSession()

    try:
        encoded = name.replace("/", "%2F")
        url = f"https://registry.npmjs.org/{encoded}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                return ctx
            data = await resp.json(content_type=None)
    except Exception as e:
        logger.debug(f"npm metadata fetch failed for {name}: {e}")
        return ctx
    finally:
        if close:
            await session.close()

    time_data = data.get("time", {})
    versions = data.get("versions", {})

    # --- Signal: Dormancy ---
    old_ts_str = time_data.get(old_version)
    new_ts_str = time_data.get(new_version)
    if old_ts_str and new_ts_str:
        try:
            old_ts = datetime.fromisoformat(old_ts_str.replace("Z", "+00:00"))
            new_ts = datetime.fromisoformat(new_ts_str.replace("Z", "+00:00"))
            gap_days = (new_ts - old_ts).days
            ctx.days_since_last_release = gap_days
            if gap_days > 365:
                ctx.signals.append(VersionSignal(
                    signal_id="LONG_DORMANCY",
                    description=f"前回リリースから{gap_days}日ぶりの更新（休眠パッケージの復活）",
                    severity="HIGH",
                    confidence_boost=0.15,
                ))
        except Exception:
            pass

    # --- Signal: Maintainer change (npm uses maintainers array) ---
    old_meta = versions.get(old_version, {})
    new_meta = versions.get(new_version, {})

    old_maintainers = {m.get("name", "") for m in old_meta.get("maintainers", [])}
    new_maintainers = {m.get("name", "") for m in new_meta.get("maintainers", [])}

    if old_maintainers and new_maintainers and old_maintainers != new_maintainers:
        added = new_maintainers - old_maintainers
        removed = old_maintainers - new_maintainers
        if added or removed:
            ctx.maintainer_changed = True
            ctx.signals.append(VersionSignal(
                signal_id="MAINTAINER_CHANGE",
                description=f"メンテナーが変更された（追加: {added}, 削除: {removed}）",
                severity="HIGH",
                confidence_boost=0.20,
            ))

    # --- Signal: New suspicious dependencies ---
    old_deps = set(old_meta.get("dependencies", {}).keys())
    new_deps = set(new_meta.get("dependencies", {}).keys())
    added_deps = new_deps - old_deps

    # Flag newly added deps that are very new or have low download count (heuristic: unknown pkg)
    for dep in added_deps:
        if dep not in {"lodash", "express", "axios", "react", "typescript"}:  # well-known whitelist
            ctx.new_suspicious_deps.append(dep)

    if ctx.new_suspicious_deps:
        ctx.signals.append(VersionSignal(
            signal_id="NEW_DEPENDENCY",
            description=f"新しい依存パッケージが追加された: {', '.join(ctx.new_suspicious_deps[:3])}",
            severity="MEDIUM",
            confidence_boost=0.08,
        ))

    # --- Signal: New postinstall/preinstall ---
    old_scripts = old_meta.get("scripts", {})
    new_scripts = new_meta.get("scripts", {})
    new_hooks = {k for k in ("postinstall", "preinstall", "install") if k in new_scripts and k not in old_scripts}
    if new_hooks:
        ctx.new_install_hook = True
        ctx.signals.append(VersionSignal(
            signal_id="NEW_INSTALL_HOOK",
            description=f"インストールフックが追加された: {', '.join(new_hooks)}",
            severity="CRITICAL",
            confidence_boost=0.30,
        ))

    return ctx


async def get_transition_context(
    name: str,
    old_version: str,
    new_version: str,
    ecosystem: str,
) -> Optional[VersionTransitionContext]:
    """Get version transition context for any ecosystem."""
    if not old_version:
        return None
    try:
        if ecosystem == "pypi":
            return await analyze_pypi_transition(name, old_version, new_version)
        elif ecosystem == "npm":
            return await analyze_npm_transition(name, old_version, new_version)
    except Exception as e:
        logger.warning(f"Version transition analysis failed for {name}: {e}")
    return None


async def _get_version_info_pypi(name: str, version: str) -> Optional[dict]:
    """Get PyPI version-specific metadata."""
    try:
        url = f"https://pypi.org/pypi/{name}/{version}/json"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("info", {})
    except Exception:
        pass
    return None


def _extract_upload_time(files: list[dict]) -> Optional[datetime]:
    """Extract the earliest upload time from a list of release files."""
    times = []
    for f in files:
        ts_str = f.get("upload_time_iso_8601") or f.get("upload_time", "")
        if ts_str:
            try:
                times.append(datetime.fromisoformat(ts_str.replace("Z", "+00:00")))
            except Exception:
                pass
    return min(times) if times else None


async def analyze_diff_stats_signals(
    diff_stats,
    package_name: str,
    ecosystem: str,
) -> list[VersionSignal]:
    """
    Derive suspicious signals from DiffStats.

    These signals don't require network calls — they use data already computed
    from the diff itself.
    """
    signals: list[VersionSignal] = []

    if diff_stats is None:
        return signals

    total_added = diff_stats.lines_added
    total_removed = diff_stats.lines_removed
    new_files = diff_stats.new_files
    deleted_files = diff_stats.deleted_files
    binary_files = diff_stats.binary_files

    # Signal: Massive code addition relative to deletion (inject-heavy)
    if total_removed > 0 and total_added / max(total_removed, 1) > 5:
        if total_added > 50:
            signals.append(VersionSignal(
                signal_id="LARGE_ADDITION",
                description=f"削除{total_removed}行に対して追加{total_added}行（注入型変更の疑い）",
                severity="MEDIUM",
                confidence_boost=0.05,
            ))
    elif total_removed == 0 and total_added > 100:
        # Pure addition with no removals — very common in backdoor injection
        signals.append(VersionSignal(
            signal_id="PURE_ADDITION",
            description=f"既存コードへの純粋追加（{total_added}行）—削除なし",
            severity="MEDIUM",
            confidence_boost=0.07,
        ))

    # Signal: Test files deleted (attackers remove tests to avoid detection)
    test_files_deleted = [
        f for f in deleted_files
        if any(pat in f for pat in ("test_", "_test", ".spec.", ".test.", "/test/", "/tests/"))
    ]
    if test_files_deleted and len(test_files_deleted) >= 2:
        signals.append(VersionSignal(
            signal_id="TESTS_DELETED",
            description=f"テストファイルが{len(test_files_deleted)}件削除された（悪意コードのテスト検出回避の疑い）",
            severity="HIGH",
            confidence_boost=0.15,
        ))

    # Signal: Binary files added (potential payload embedding)
    suspicious_binaries = [
        f for f in binary_files
        if any(f.endswith(ext) for ext in (".so", ".dll", ".exe", ".bin", ".pyc"))
        and not f.endswith(".pyc")  # compiled python is normal
    ]
    if suspicious_binaries:
        signals.append(VersionSignal(
            signal_id="BINARY_ADDED",
            description=f"実行可能バイナリが追加された: {', '.join(suspicious_binaries[:2])}",
            severity="HIGH",
            confidence_boost=0.20,
        ))

    # Signal: Setup/build files modified (install-time execution vector)
    build_files_changed = [
        f for f in (new_files + [f for f in deleted_files])
        if any(pat in f for pat in ("setup.py", "pyproject.toml", "package.json", "binding.gyp"))
    ]
    if build_files_changed:
        signals.append(VersionSignal(
            signal_id="BUILD_FILES_CHANGED",
            description=f"ビルドファイルが変更された: {', '.join(build_files_changed[:2])}",
            severity="MEDIUM",
            confidence_boost=0.08,
        ))

    return signals


async def analyze_zero_code_change_signal(
    diff_stats,
    new_deps: list,
    ecosystem: str = "",
) -> list:
    """
    Detect the axios-style attack pattern:
    "source code changed 0 lines, but new dependency added"

    This is one of the strongest indicators of a supply chain injection:
    legitimate maintainers rarely add dependencies without any code changes
    that USE those dependencies.

    Parameters:
        diff_stats: DiffStats object
        new_deps: list of NewDependency from dep_extractor
        ecosystem: "npm" | "pypi" etc.

    Returns:
        list of VersionSignal
    """
    signals = []

    if not new_deps or diff_stats is None:
        return signals

    # Heuristic: if total lines_added is very small relative to new deps,
    # it's likely only manifest changes
    # (diff_stats doesn't separate by file type, so we use a threshold)
    total_lines = diff_stats.lines_added + diff_stats.lines_removed

    # Core detection: total code changes are small (< 10 lines)
    # but new dependencies were added
    # This catches: package.json changes only
    # Strongest signal: exactly 0 lines of code changed + new dep added
    if total_lines == 0 and new_deps:
        dep_names = [d.name for d in new_deps[:3]]
        signals.append(VersionSignal(
            signal_id="MANIFEST_ONLY_NEW_DEP",
            description=(
                f"コード変更ゼロかつ新規依存追加: {', '.join(dep_names)}"
                f" — サプライチェーン攻撃の最高リスクパターン"
            ),
            severity="CRITICAL",
            confidence_boost=0.35,
        ))

    # Strong signal: very few lines changed (1-5) + new dep added
    elif total_lines <= 5 and new_deps:
        dep_names = [d.name for d in new_deps[:3]]
        signals.append(VersionSignal(
            signal_id="ZERO_CODE_CHANGE_WITH_NEW_DEP",
            description=(
                f"ソースコード変更わずか{total_lines}行にもかかわらず"
                f"新規依存パッケージが追加された: {', '.join(dep_names)}"
                f" — axios 2026年攻撃と同一パターン"
            ),
            severity="HIGH",
            confidence_boost=0.25,
        ))

    # Also flag if: large number of new deps added at once (unusual for minor versions)
    if len(new_deps) >= 3:
        dep_names = [d.name for d in new_deps[:5]]
        signals.append(VersionSignal(
            signal_id="MANY_NEW_DEPS_AT_ONCE",
            description=(
                f"一度に{len(new_deps)}個の新規依存パッケージが追加された: "
                f"{', '.join(dep_names[:3])}{'...' if len(dep_names) > 3 else ''}"
            ),
            severity="MEDIUM",
            confidence_boost=0.10,
        ))

    return signals
