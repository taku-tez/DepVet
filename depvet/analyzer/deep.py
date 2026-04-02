"""Stage 2: Deep analysis pipeline and VerdictMerger."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from depvet.analyzer.base import BaseAnalyzer
from depvet.differ.chunker import DiffChunk
from depvet.analyzer.rules import RuleMatch
from depvet.analyzer.version_signal import VersionTransitionContext
from depvet.models.verdict import (
    DiffStats,
    Finding,
    FindingCategory,
    Severity,
    Verdict,
    VerdictType,
)

logger = logging.getLogger(__name__)

VERDICT_PRIORITY = {
    VerdictType.MALICIOUS: 4,
    VerdictType.SUSPICIOUS: 3,
    VerdictType.BENIGN: 2,
    VerdictType.UNKNOWN: 1,
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.NONE: 1,
}


def _parse_finding(raw: dict) -> Optional[Finding]:
    try:
        return Finding(
            category=FindingCategory(raw["category"]),
            description=raw.get("description", ""),
            file=raw.get("file", ""),
            line_start=raw.get("line_start"),
            line_end=raw.get("line_end"),
            evidence=raw.get("evidence", "")[:50],
            cwe=raw.get("cwe"),
            severity=Severity(raw.get("severity", "LOW")),
        )
    except (KeyError, ValueError) as e:
        logger.warning(f"Failed to parse finding: {e} | raw={raw}")
        return None


class VerdictMerger:
    """
    Merges Verdict results from multiple diff chunks into one.

    Merge rules:
    - verdict: strictest wins (MALICIOUS > SUSPICIOUS > BENIGN > UNKNOWN)
    - severity: highest wins
    - confidence: weighted average by number of findings
    - findings: union, deduplicated by (file, category)
    - summary: take summary from the most severe chunk
    """

    def merge(self, raw_verdicts: list[dict], model: str, diff_stats: DiffStats, start_ms: int, rule_matches: list | None = None, version_context: VersionTransitionContext | None = None) -> Verdict:
        if not raw_verdicts:
            return Verdict(
                verdict=VerdictType.UNKNOWN,
                severity=Severity.NONE,
                confidence=0.0,
                findings=[],
                summary="分析結果なし",
                analysis_duration_ms=int(time.time() * 1000) - start_ms,
                diff_stats=diff_stats,
                model=model,
                analyzed_at=datetime.now(timezone.utc).isoformat(),
                chunks_analyzed=0,
                tokens_used=0,
            )

        # Find strictest verdict
        best_verdict_raw = max(
            raw_verdicts,
            key=lambda r: VERDICT_PRIORITY.get(
                VerdictType(r.get("verdict", "UNKNOWN")), 0
            ),
        )
        best_verdict_type = VerdictType(best_verdict_raw.get("verdict", "UNKNOWN"))

        # Find highest severity
        all_severities = [Severity(r.get("severity", "NONE")) for r in raw_verdicts]
        best_severity = max(all_severities, key=lambda s: SEVERITY_ORDER.get(s, 0))

        # Weighted confidence
        total_findings = sum(len(r.get("findings", [])) for r in raw_verdicts)
        if total_findings == 0:
            confidence = sum(r.get("confidence", 0.5) for r in raw_verdicts) / len(raw_verdicts)
        else:
            weighted = sum(
                r.get("confidence", 0.5) * len(r.get("findings", []))
                for r in raw_verdicts
            )
            confidence = weighted / total_findings

        # Deduplicate findings by (file, category)
        seen: set[tuple[str, str]] = set()
        merged_findings: list[Finding] = []
        for r in raw_verdicts:
            for raw_f in r.get("findings", []):
                f = _parse_finding(raw_f)
                if f is None:
                    continue
                key = (f.file, f.category.value)
                if key not in seen:
                    seen.add(key)
                    merged_findings.append(f)

        # Use summary from most severe chunk
        summary_chunk = max(
            raw_verdicts,
            key=lambda r: SEVERITY_ORDER.get(Severity(r.get("severity", "NONE")), 0),
        )
        summary = summary_chunk.get("summary", "")

        tokens_used = sum(r.get("_tokens_used", 0) for r in raw_verdicts)

        # Inject rule-based findings (if not already covered by LLM findings)
        if rule_matches:
            rule_keys = {(f.file, f.category.value) for f in merged_findings}
            for rm in rule_matches:
                key = (rm.file, rm.category.value)
                if key not in rule_keys:
                    merged_findings.append(Finding(
                        category=rm.category,
                        description=rm.description,
                        file=rm.file,
                        line_start=rm.line_number,
                        line_end=rm.line_number,
                        evidence=rm.evidence,
                        cwe=rm.cwe,
                        severity=rm.severity,
                    ))
                    rule_keys.add(key)

            # Escalate verdict if rule matches are more severe
            from depvet.analyzer.rules import RuleMatch as _RM
            rule_severities = [rm.severity for rm in rule_matches]
            rule_best = max(rule_severities, key=lambda s: SEVERITY_ORDER.get(s, 0))
            if SEVERITY_ORDER.get(rule_best, 0) > SEVERITY_ORDER.get(best_severity, 0):
                best_severity = rule_best

            if rule_matches and best_verdict_type == VerdictType.BENIGN:
                best_verdict_type = VerdictType.SUSPICIOUS
                if any(rm.severity.value in ("CRITICAL", "HIGH") for rm in rule_matches):
                    best_verdict_type = VerdictType.MALICIOUS

        # Apply version transition signal escalation
        if version_context and version_context.signals:
            # Boost confidence
            confidence = min(1.0, confidence + version_context.total_confidence_boost)

            has_critical_rule = any(
                getattr(m, "severity", None) and m.severity.value == "CRITICAL"
                for m in (rule_matches or [])
            )
            has_high_version_signal = version_context.has_high_risk_signals
            llm_high_confidence_benign = (
                best_verdict_type == VerdictType.BENIGN and confidence > 0.90
            )

            # Escalation rules (with high-confidence BENIGN protection):
            # Rule A: CRITICAL rule + HIGH signal → MALICIOUS (always, even high-conf benign)
            # Rule B: BENIGN + HIGH signal, but LLM confidence < 0.90 → SUSPICIOUS
            # Rule C: BENIGN + HIGH signal, LLM confidence >= 0.90 + no CRITICAL rule → keep BENIGN
            if has_critical_rule and has_high_version_signal:
                best_verdict_type = VerdictType.MALICIOUS
            elif best_verdict_type == VerdictType.BENIGN and has_high_version_signal:
                if not llm_high_confidence_benign:
                    best_verdict_type = VerdictType.SUSPICIOUS
                # else: trust high-confidence LLM BENIGN verdict (Rule C)

            # Append version signals to summary
            if version_context.summary():
                summary = (summary + "\n" + version_context.summary()).strip()

        return Verdict(
            verdict=best_verdict_type,
            severity=best_severity,
            confidence=round(min(1.0, max(0.0, confidence)), 3),
            findings=merged_findings,
            summary=summary,
            analysis_duration_ms=int(time.time() * 1000) - start_ms,
            diff_stats=diff_stats,
            model=model,
            analyzed_at=datetime.now(timezone.utc).isoformat(),
            chunks_analyzed=len(raw_verdicts),
            tokens_used=tokens_used,
        )


class DeepAnalyzer:
    """
    Stage 2: Deep analysis across all chunks, then merge results.
    """

    def __init__(self, analyzer: BaseAnalyzer, merger: Optional[VerdictMerger] = None):
        self.analyzer = analyzer
        self.merger = merger or VerdictMerger()

    async def analyze(
        self,
        chunks: list[DiffChunk],
        package_name: str,
        old_version: str,
        new_version: str,
        ecosystem: str,
        diff_stats: DiffStats,
        rule_matches: list | None = None,
        version_context: VersionTransitionContext | None = None,
    ) -> Verdict:
        start_ms = int(time.time() * 1000)
        total = len(chunks)

        tasks = [
            self.analyzer.deep_analyze(
                chunk=chunk,
                chunk_index=i,
                total_chunks=total,
                package_name=package_name,
                old_version=old_version,
                new_version=new_version,
                ecosystem=ecosystem,
            )
            for i, chunk in enumerate(chunks)
        ]

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results = []
        for i, result in enumerate(raw_results):
            if isinstance(result, Exception):
                logger.error(f"Chunk {i} analysis failed: {result}")
            else:
                valid_results.append(result)

        return self.merger.merge(
            raw_verdicts=valid_results,
            model=self.analyzer.get_model_name(),
            diff_stats=diff_stats,
            start_ms=start_ms,
            rule_matches=rule_matches or [],
            version_context=version_context,
        )
