"""Stage 1: Triage analysis pipeline."""

from __future__ import annotations

import asyncio
import logging

import aiohttp

from depvet.analyzer.base import BaseAnalyzer
from depvet.analyzer.rules import scan_diff_full, is_likely_benign, RuleMatch
from depvet.analyzer.import_diff import analyze_imports
from depvet.analyzer.decode_scan import decode_and_scan
from depvet.analyzer.ast_scan import ast_scan_diff
from depvet.analyzer.dep_extractor import extract_new_dependencies, deps_to_watchlist_entries
from depvet.analyzer.dep_reputation import evaluate_dep_reputation
from depvet.differ.chunker import DiffChunk
from depvet.models.verdict import FindingCategory, Severity

logger = logging.getLogger(__name__)


class TriageAnalyzer:
    """
    Stage 1: Quick triage of diff chunks.

    Four-phase approach (no LLM cost):
    1. Rule-based scan (single-line + window patterns)
    2. Import diff analysis (new suspicious modules)
    3. Base64/hex decode + re-scan (hidden payloads)
    4. AST analysis (obfuscation: getattr/chr/aliased exec)

    Falls through to LLM only when rules are inconclusive.
    """

    def __init__(self, analyzer: BaseAnalyzer):
        self.analyzer = analyzer

    async def should_analyze(
        self,
        chunks: list[DiffChunk],
        package_name: str,
        old_version: str,
        new_version: str,
    ) -> tuple[bool, str, list[RuleMatch]]:
        """
        Returns (should_deep_analyze, reason, rule_matches).
        rule_matches includes hits from all static analysis phases.
        """
        if not chunks:
            return False, "no diff chunks", []

        # ── Phase 1: Rule-based (single + window) ──────────────────────────
        all_rule_matches: list[RuleMatch] = []
        for chunk in chunks:
            for f in chunk.files:
                if not f.is_binary and f.content:
                    matches = scan_diff_full(f.content, f.path)
                    all_rule_matches.extend(matches)

        critical_rules = [m for m in all_rule_matches if m.severity.value == "CRITICAL"]
        if critical_rules:
            return True, f"ルールエンジン(CRITICAL): {critical_rules[0].description}", all_rule_matches

        # ── Phase 2: Import diff analysis ──────────────────────────────────
        for chunk in chunks:
            for f in chunk.files:
                if not f.is_binary and f.content and f.path.endswith((".py", ".js", ".ts", "")):
                    import_signals = analyze_imports(f.content)
                    if any(s.severity in ("CRITICAL", "HIGH") for s in import_signals):
                        # Convert import signals to RuleMatch-like objects
                        for sig in import_signals:
                            if sig.severity in ("CRITICAL", "HIGH"):
                                all_rule_matches.append(
                                    RuleMatch(
                                        rule_id=f"IMPORT_{sig.module.upper().replace('.', '_')}",
                                        category=FindingCategory.EXECUTION,
                                        severity=Severity(sig.severity),
                                        description=sig.description,
                                        evidence=f"import {sig.module}",
                                        file=f.path,
                                        line_number=sig.line_number,
                                        cwe="CWE-913",
                                    )
                                )
                        if any(s.severity == "CRITICAL" for s in import_signals):
                            return True, f"新規危険インポート検出: {import_signals[0].module}", all_rule_matches

        # ── Phase 2.5: Dependency manifest check ──────────────────────────
        # Detect newly added dependencies (e.g., axios attack: plain-crypto-js injected)
        for chunk in chunks:
            for f in chunk.files:
                if not f.is_binary and f.content:
                    fname = f.path.lower()
                    if any(m in fname for m in ("package.json", "pyproject.toml", "setup.cfg", "requirements")):
                        new_deps = extract_new_dependencies(f.content, f.path)
                        if new_deps:
                            # Check against Known-bad DB
                            from depvet.known_bad.database import KnownBadDB

                            db = KnownBadDB()
                            for dep in new_deps:
                                hit = db.lookup(dep.name, dep.version_spec.lstrip("^~>=<"), dep.ecosystem)
                                if hit:
                                    all_rule_matches.append(
                                        RuleMatch(
                                            rule_id="KNOWN_BAD_DEP_INJECTED",
                                            category=FindingCategory.DEPENDENCY_CONFUSION,
                                            severity=Severity.CRITICAL,
                                            description=f"既知の悪意あるパッケージ '{dep.name}@{dep.version_spec}' が依存として追加された: {hit.summary}",
                                            evidence=f"{dep.name}: {dep.version_spec}",
                                            file=f.path,
                                            line_number=dep.line_number,
                                            cwe="CWE-829",
                                        )
                                    )
                                    return (
                                        True,
                                        f"Known-bad依存追加検出: {dep.name}@{dep.version_spec}",
                                        all_rule_matches,
                                    )

                            # ── Reputation check for each new dependency ──
                            unknown_deps = deps_to_watchlist_entries(new_deps)
                            if unknown_deps:
                                for dep_name, dep_eco in unknown_deps[:5]:
                                    try:
                                        rep = await evaluate_dep_reputation(dep_name, dep_eco, "")
                                        if rep.severity in ("CRITICAL", "HIGH"):
                                            sev_val = Severity(rep.severity)
                                            all_rule_matches.append(
                                                RuleMatch(
                                                    rule_id="SUSPICIOUS_NEW_DEP_REPUTATION",
                                                    category=FindingCategory.DEPENDENCY_CONFUSION,
                                                    severity=sev_val,
                                                    description=rep.description
                                                    or f"新規依存パッケージ '{dep_name}' の信頼性が低い: {', '.join(rep.signals[:2])}",
                                                    evidence=f"{dep_name}: age={rep.age_days}d dl={rep.weekly_downloads}",
                                                    file=f.path,
                                                    line_number=None,
                                                    cwe="CWE-1021",
                                                )
                                            )
                                            if rep.severity == "CRITICAL":
                                                return (
                                                    True,
                                                    f"信頼性不明の新規依存検出: {dep_name}（公開{rep.age_days}日、DL:{rep.weekly_downloads}）",
                                                    all_rule_matches,
                                                )
                                        elif rep.severity == "MEDIUM":
                                            all_rule_matches.append(
                                                RuleMatch(
                                                    rule_id="UNKNOWN_DEP_ADDED",
                                                    category=FindingCategory.DEPENDENCY_CONFUSION,
                                                    severity=Severity.MEDIUM,
                                                    description=f"新規依存パッケージ '{dep_name}' が追加された（信頼性要確認）",
                                                    evidence=f"new dep: {dep_name}",
                                                    file=f.path,
                                                    line_number=None,
                                                    cwe="CWE-1021",
                                                )
                                            )
                                    except (aiohttp.ClientError, asyncio.TimeoutError) as rep_err:
                                        logger.debug(f"Reputation check failed for {dep_name}: {rep_err}")
                                        all_rule_matches.append(
                                            RuleMatch(
                                                rule_id="UNKNOWN_DEP_ADDED",
                                                category=FindingCategory.DEPENDENCY_CONFUSION,
                                                severity=Severity.MEDIUM,
                                                description=f"未知の依存パッケージ '{dep_name}' が追加された（信頼性確認失敗）",
                                                evidence=f"new dep: {dep_name}",
                                                file=f.path,
                                                line_number=None,
                                                cwe="CWE-1021",
                                            )
                                        )

        # ── Phase 3: Base64/hex decode scan ────────────────────────────────
        for chunk in chunks:
            for f in chunk.files:
                if not f.is_binary and f.content:
                    decoded_hits = decode_and_scan(f.content, f.path)
                    if decoded_hits:
                        critical_decoded = [d for d in decoded_hits if d.severity == Severity.CRITICAL]
                        if critical_decoded:
                            for d in critical_decoded:
                                all_rule_matches.append(
                                    RuleMatch(
                                        rule_id="DECODED_PAYLOAD_CRITICAL",
                                        category=d.category,
                                        severity=d.severity,
                                        description=d.description,
                                        evidence=d.original_encoded,
                                        file=d.file,
                                        line_number=d.line_number,
                                        cwe=d.cwe,
                                    )
                                )
                            return True, f"エンコードされたペイロード検出({decoded_hits[0].encoding})", all_rule_matches

        # ── Phase 4: AST analysis ───────────────────────────────────────────
        for chunk in chunks:
            for f in chunk.files:
                if not f.is_binary and f.content and f.path.endswith((".py", ".pyw", "")):
                    ast_findings = ast_scan_diff(f.content, f.path)
                    critical_ast = [a for a in ast_findings if a.severity.value == "CRITICAL"]
                    if critical_ast:
                        for a in critical_ast:
                            all_rule_matches.append(
                                RuleMatch(
                                    rule_id=a.finding_id,
                                    category=a.category,
                                    severity=a.severity,
                                    description=a.description,
                                    evidence=a.evidence,
                                    file=f.path,
                                    line_number=a.line_number,
                                    cwe=a.cwe,
                                )
                            )
                        return True, f"AST解析(CRITICAL): {critical_ast[0].description}", all_rule_matches

        # ── Check if likely benign (skip LLM) ──────────────────────────────
        all_content = " ".join(f.content for chunk in chunks for f in chunk.files if not f.is_binary)
        if is_likely_benign(all_content) and not all_rule_matches:
            return False, "コメント/ドキュメント変更のみ（静的解析判定）", []

        # ── HIGH rule matches → still LLM analyze ──────────────────────────
        high_rules = [m for m in all_rule_matches if m.severity.value == "HIGH"]
        if high_rules:
            return True, f"ルールエンジン(HIGH): {high_rules[0].description}", all_rule_matches

        # ── Phase 5: LLM triage as final arbiter ───────────────────────────
        try:
            should, reason = await self.analyzer.triage(chunks[0], package_name, old_version, new_version)
        except Exception as e:  # LLM SDK may raise various errors; fail-safe to analyze
            logger.warning(f"LLM triage failed, defaulting to analyze: {e}")
            return True, f"LLM triage error (fail-safe): {e}", all_rule_matches
        if should:
            return True, reason, all_rule_matches

        # Check remaining chunks for binary/new files
        for chunk in chunks[1:]:
            for f in chunk.files:
                if f.is_binary or f.is_new:
                    return True, f"バイナリ/新規ファイル: {f.path}", all_rule_matches

        return False, reason, all_rule_matches
