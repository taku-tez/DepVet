"""Stdout alerter with Rich formatting."""

from __future__ import annotations

import json
from typing import Optional

from depvet.models.alert import AlertEvent
from depvet.models.verdict import Severity, VerdictType

try:
    from rich.console import Console
    _RICH = True
except ImportError:
    _RICH = False

console = Console() if _RICH else None  # type: ignore

VERDICT_COLORS = {
    VerdictType.MALICIOUS: "bold red",
    VerdictType.SUSPICIOUS: "bold yellow",
    VerdictType.BENIGN: "bold green",
    VerdictType.UNKNOWN: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🚨",
    Severity.HIGH: "⚠️",
    Severity.MEDIUM: "🔶",
    Severity.LOW: "🔷",
    Severity.NONE: "✅",
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
    Severity.LOW: 2, Severity.NONE: 1,
}


def format_alert_text(event: AlertEvent) -> str:
    """Format an alert event as plain text."""
    v = event.verdict
    r = event.release
    icon = SEVERITY_ICONS.get(v.severity, "")
    lines = [
        "━" * 40,
        f"{icon} {v.verdict.value} RELEASE DETECTED",
        "━" * 40,
        f"Package   : {r.name} ({r.ecosystem.upper()})",
        f"Version   : {r.previous_version or '(new)'} → {r.version}",
        f"Verdict   : {v.verdict.value}",
        f"Severity  : {v.severity.value}",
        f"Confidence: {v.confidence:.2f}",
        "",
    ]
    if v.findings:
        lines.append("Findings:")
        for i, f in enumerate(v.findings, 1):
            cwe = f" ({f.cwe})" if f.cwe else ""
            loc = f" (L{f.line_start}-L{f.line_end})" if f.line_start else ""
            lines.append(f"  [{i}] {f.category.value}{cwe}")
            lines.append(f"      File: {f.file}{loc}")
            lines.append(f"      {f.description}")
    lines.append("")
    if v.summary:
        lines.append("Summary:")
        lines.append(f"  {v.summary}")
    lines.append("")
    lines.append(f"URL: {r.url}")
    lines.append("━" * 40)
    return "\n".join(lines)


class StdoutAlerter:
    """Prints alerts to stdout using Rich (or plain text fallback)."""

    def __init__(self, json_mode: bool = False, min_severity: str = "MEDIUM"):
        self.json_mode = json_mode
        self.min_severity = Severity(min_severity)

    async def send(self, event: AlertEvent) -> None:
        if SEVERITY_ORDER.get(event.verdict.severity, 0) < SEVERITY_ORDER.get(self.min_severity, 0):
            return

        if self.json_mode:
            print(json.dumps({
                "package": event.release.name,
                "version": event.release.version,
                "ecosystem": event.release.ecosystem,
                "previous_version": event.release.previous_version,
                "verdict": event.verdict.verdict.value,
                "severity": event.verdict.severity.value,
                "confidence": event.verdict.confidence,
                "findings_count": len(event.verdict.findings),
                "summary": event.verdict.summary,
                "url": event.release.url,
            }, ensure_ascii=False, indent=2))
        elif _RICH and console:
            text = format_alert_text(event)
            color = VERDICT_COLORS.get(event.verdict.verdict, "white")
            console.print(text, style=color if event.verdict.verdict != VerdictType.BENIGN else "green")
        else:
            print(format_alert_text(event))
