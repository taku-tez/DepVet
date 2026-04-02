"""Rich console output for dependency verdicts."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from depvet.models.alert import AlertEvent
from depvet.models.verdict import VerdictType, Severity

console = Console()

_VERDICT_STYLES = {
    VerdictType.MALICIOUS: ("bold red", "MALICIOUS RELEASE DETECTED"),
    VerdictType.SUSPICIOUS: ("bold yellow", "SUSPICIOUS RELEASE DETECTED"),
    VerdictType.BENIGN: ("bold green", "BENIGN RELEASE"),
    VerdictType.UNKNOWN: ("bold dim", "UNKNOWN VERDICT"),
}

_SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.NONE: "dim",
}


class StdoutAlert:
    """Displays formatted alert output on the terminal using Rich."""

    def __init__(self) -> None:
        self.console = console

    def send(self, alert_event: AlertEvent) -> None:
        """Render an alert event to stdout with Rich formatting."""
        release = alert_event.release
        verdict = alert_event.verdict

        style, headline = _VERDICT_STYLES.get(
            verdict.verdict, ("bold dim", "RELEASE UPDATE")
        )
        severity_style = _SEVERITY_STYLES.get(verdict.severity, "dim")

        # --- Header banner ---------------------------------------------------
        self.console.print()
        self.console.rule(style=style)
        self.console.print(
            Text(f"\U0001f6a8 {headline}", style=style, justify="center")
        )
        self.console.rule(style=style)

        # --- Summary table ----------------------------------------------------
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold", min_width=12)
        table.add_column("Value")

        version_str = (
            f"{release.previous_version} \u2192 {release.version}"
            if release.previous_version
            else release.version
        )

        table.add_row("Package", f"{release.name} ({release.ecosystem})")
        table.add_row("Version", version_str)
        table.add_row("Verdict", Text(verdict.verdict.value, style=style))
        table.add_row("Severity", Text(verdict.severity.value, style=severity_style))
        table.add_row("Confidence", f"{verdict.confidence:.2f}")
        table.add_row("Summary", verdict.summary)
        table.add_row("Analyzed at", verdict.analyzed_at)
        table.add_row("Model", verdict.model)

        self.console.print(table)

        # --- Diff stats -------------------------------------------------------
        ds = verdict.diff_stats
        self.console.print()
        self.console.print(
            f"  [bold]Diff:[/bold]  {ds.files_changed} files changed, "
            f"[green]+{ds.lines_added}[/green] / [red]-{ds.lines_removed}[/red]"
        )

        if ds.new_files:
            self.console.print(f"  [bold]New files:[/bold]  {', '.join(ds.new_files)}")
        if ds.deleted_files:
            self.console.print(
                f"  [bold]Deleted:[/bold]   {', '.join(ds.deleted_files)}"
            )

        # --- Findings ---------------------------------------------------------
        if verdict.findings:
            self.console.print()
            findings_table = Table(
                title="Findings",
                title_style="bold",
                expand=True,
            )
            findings_table.add_column("#", style="dim", width=3)
            findings_table.add_column("Category", style="bold")
            findings_table.add_column("Severity")
            findings_table.add_column("File")
            findings_table.add_column("Description", ratio=2)

            for idx, finding in enumerate(verdict.findings, start=1):
                f_sev_style = _SEVERITY_STYLES.get(finding.severity, "dim")
                findings_table.add_row(
                    str(idx),
                    finding.category.value,
                    Text(finding.severity.value, style=f_sev_style),
                    finding.file,
                    finding.description,
                )

            self.console.print(findings_table)

        # --- Affected tenants -------------------------------------------------
        if alert_event.affected_tenants:
            self.console.print()
            self.console.print(
                f"  [bold]Affected tenants:[/bold]  "
                f"{', '.join(alert_event.affected_tenants)}"
            )

        self.console.print()
        self.console.rule(style=style)
        self.console.print()
