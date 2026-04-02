"""Stage 1: Triage analysis pipeline."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from depvet.analyzer.base import BaseAnalyzer
from depvet.analyzer.rules import scan_diff, is_likely_benign, RuleMatch
from depvet.differ.chunker import DiffChunk

logger = logging.getLogger(__name__)


class TriageAnalyzer:
    """
    Stage 1: Quick triage of diff chunks.

    Two-phase approach:
    1. Rule-based pre-screening (fast, no LLM cost)
       - Immediate flag: hardcoded IPs, base64+exec, credential access
       - Immediate skip: doc/comment-only diffs
    2. LLM triage (only if rules don't give a definitive answer)
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
        Run triage on diff chunks.
        Returns (should_deep_analyze, reason, rule_matches).

        rule_matches are pre-found IOCs that can seed the deep analysis.
        """
        if not chunks:
            return False, "no diff chunks", []

        # Phase 1: Rule-based scan across all chunks
        all_rule_matches: list[RuleMatch] = []
        for chunk in chunks:
            for f in chunk.files:
                if not f.is_binary and f.content:
                    matches = scan_diff(f.content, f.path)
                    all_rule_matches.extend(matches)

        if all_rule_matches:
            # Critical/High rule matches → immediate analyze
            critical = [m for m in all_rule_matches if m.severity.value in ("CRITICAL", "HIGH")]
            if critical:
                reasons = list({m.description for m in critical[:2]})
                return True, f"ルールベース検出: {reasons[0]}", all_rule_matches

        # Phase 1b: Check if diff is likely benign (skip LLM)
        all_content = " ".join(
            f.content for chunk in chunks for f in chunk.files
            if not f.is_binary
        )
        if is_likely_benign(all_content) and not all_rule_matches:
            return False, "コメント/ドキュメント変更のみ（ルールベース判定）", []

        # Phase 2: LLM triage on first chunk (priority files)
        should, reason = await self.analyzer.triage(
            chunks[0], package_name, old_version, new_version
        )

        if should:
            return True, reason, all_rule_matches

        # Check remaining chunks for binary/new files
        for chunk in chunks[1:]:
            for f in chunk.files:
                if f.is_binary or f.is_new:
                    return True, f"バイナリ/新規ファイル: {f.path}", all_rule_matches

        return False, reason, all_rule_matches
