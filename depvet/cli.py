"""DepVet CLI entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Optional

import click

from depvet import __version__

try:
    from rich.console import Console
    from rich.table import Table
    _RICH = True
    console = Console()
except ImportError:
    _RICH = False
    console = None  # type: ignore

logger = logging.getLogger("depvet")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _get_analyzer(config):
    """Create analyzer from config."""
    from depvet.analyzer.claude import ClaudeAnalyzer
    from depvet.analyzer.openai import OpenAIAnalyzer

    provider = config.llm.provider.lower()
    api_key = os.environ.get(config.llm.api_key_env)

    if provider == "openai":
        return OpenAIAnalyzer(
            model=config.llm.model,
            triage_model=config.llm.triage_model if hasattr(config.llm, 'triage_model') else "gpt-4o-mini",
            api_key=api_key,
            max_tokens=config.llm.max_tokens,
        )
    else:
        return ClaudeAnalyzer(
            model=config.llm.model,
            triage_model=config.llm.triage_model,
            api_key=api_key,
            max_tokens=config.llm.max_tokens,
        )


@click.group()
@click.version_option(__version__, prog_name="depvet")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--config", "-c", type=click.Path(), default=None, help="Path to depvet.toml")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, config: Optional[str]) -> None:
    """DepVet — Software supply chain monitoring engine."""
    _setup_logging(verbose)
    ctx.ensure_object(dict)
    from depvet.config.config import load_config
    ctx.obj["config"] = load_config(config)


# ─────────────────────────────────────────────────────────────
# depvet scan
# ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("package")
@click.argument("old_version")
@click.argument("new_version")
@click.option("--npm", "ecosystem", flag_value="npm", help="Use npm ecosystem")
@click.option("--pypi", "ecosystem", flag_value="pypi", default=True, help="Use PyPI (default)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.option("--model", default=None, help="Override LLM model")
@click.option("--no-triage", is_flag=True, help="Skip Stage 1 triage")
@click.pass_context
def scan(
    ctx: click.Context,
    package: str,
    old_version: str,
    new_version: str,
    ecosystem: str,
    json_output: bool,
    model: Optional[str],
    no_triage: bool,
) -> None:
    """Scan a package version diff for malicious code."""
    config = ctx.obj["config"]
    if model:
        config.llm.model = model

    asyncio.run(_scan(config, package, old_version, new_version, ecosystem, json_output, no_triage))


async def _scan(config, package, old_version, new_version, ecosystem, json_output, no_triage):
    from depvet.differ.downloader import download_package
    from depvet.differ.unpacker import unpack
    from depvet.differ.diff_generator import generate_diff
    from depvet.analyzer.triage import TriageAnalyzer
    from depvet.analyzer.deep import DeepAnalyzer
    from depvet.alert.stdout import StdoutAlert
    from depvet.models.alert import AlertEvent
    from depvet.models.package import Release
    from datetime import datetime, timezone

    click.echo(f"🔍 Scanning {ecosystem}/{package}: {old_version} → {new_version}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        click.echo("  Downloading packages...")
        old_archive = await download_package(package, old_version, ecosystem, tmp / "old")
        (tmp / "old").mkdir(parents=True, exist_ok=True)
        new_archive = await download_package(package, new_version, ecosystem, tmp / "new")
        (tmp / "new").mkdir(parents=True, exist_ok=True)

        if not old_archive or not new_archive:
            click.echo("❌ Failed to download one or both versions", err=True)
            sys.exit(1)

        click.echo("  Unpacking...")
        old_dir = unpack(old_archive, tmp / "unpacked_old")
        new_dir = unpack(new_archive, tmp / "unpacked_new")

        click.echo("  Generating diff...")
        chunks, stats = generate_diff(old_dir, new_dir, max_chunk_tokens=config.diff.max_chunk_tokens)

        if not chunks:
            click.echo("✅ No differences found.")
            return

        click.echo(f"  Diff: {stats.files_changed} files changed (+{stats.lines_added}/-{stats.lines_removed} lines), {len(chunks)} chunk(s)")

        analyzer = _get_analyzer(config)

        rule_matches = []
        if not no_triage:
            click.echo("  Stage 1: Triage...")
            triage = TriageAnalyzer(analyzer)
            should, reason, rule_matches = await triage.should_analyze(chunks, package, old_version, new_version)
            if not should:
                click.echo(f"✅ BENIGN (triage skip): {reason}")
                return
            click.echo(f"  → Analysis needed: {reason}")

        click.echo("  Stage 2: Deep analysis...")
        # Fetch version transition context
        from depvet.analyzer.version_signal import get_transition_context
        version_ctx = None
        try:
            click.echo("  Fetching version transition signals...")
            version_ctx = await get_transition_context(package, old_version, new_version, ecosystem)
            if version_ctx and version_ctx.signals:
                for sig in version_ctx.signals:
                    click.echo(f"  ⚠️  [{sig.severity}] {sig.description}")
        except Exception as e:
            logger.debug(f"Version signal fetch failed: {e}")

        deep = DeepAnalyzer(analyzer)
        verdict = await deep.analyze(
            chunks=chunks,
            package_name=package,
            old_version=old_version,
            new_version=new_version,
            ecosystem=ecosystem,
            diff_stats=stats,
            rule_matches=rule_matches,
            version_context=version_ctx,
        )

        release = Release(
            name=package,
            version=new_version,
            ecosystem=ecosystem,
            previous_version=old_version,
            published_at=datetime.now(timezone.utc).isoformat(),
            url=(f"https://pypi.org/project/{package}/{new_version}/"
                 if ecosystem == "pypi"
                 else f"https://www.npmjs.com/package/{package}/v/{new_version}"),
        )
        event = AlertEvent(release=release, verdict=verdict)

        alerter = StdoutAlert()
        alerter.send(event)


# ─────────────────────────────────────────────────────────────
# depvet diff
# ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("package")
@click.argument("old_version")
@click.argument("new_version")
@click.option("--npm", "ecosystem", flag_value="npm")
@click.option("--pypi", "ecosystem", flag_value="pypi", default=True)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file")
@click.pass_context
def diff(ctx, package, old_version, new_version, ecosystem, output):
    """Generate a diff between two package versions."""
    config = ctx.obj["config"]
    asyncio.run(_diff(config, package, old_version, new_version, ecosystem, output))


async def _diff(config, package, old_version, new_version, ecosystem, output):
    from depvet.differ.downloader import download_package
    from depvet.differ.unpacker import unpack
    from depvet.differ.diff_generator import generate_diff, format_diff_markdown

    click.echo(f"📦 Generating diff for {ecosystem}/{package}: {old_version} → {new_version}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "old").mkdir()
        (tmp / "new").mkdir()

        old_archive = await download_package(package, old_version, ecosystem, tmp / "old")
        new_archive = await download_package(package, new_version, ecosystem, tmp / "new")

        if not old_archive or not new_archive:
            click.echo("❌ Download failed", err=True)
            sys.exit(1)

        old_dir = unpack(old_archive, tmp / "unpacked_old")
        new_dir = unpack(new_archive, tmp / "unpacked_new")
        chunks, stats = generate_diff(old_dir, new_dir)
        md = format_diff_markdown(chunks, stats)

        if output:
            Path(output).write_text(md, encoding="utf-8")
            click.echo(f"✅ Diff written to {output}")
        else:
            click.echo(md)


# ─────────────────────────────────────────────────────────────
# depvet analyze
# ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("diff_file", type=click.Path(exists=True))
@click.option("--json", "json_output", is_flag=True)
@click.option("--model", default=None)
@click.option("--package", default="unknown")
@click.option("--old-version", default="unknown")
@click.option("--new-version", default="unknown")
@click.option("--ecosystem", default="pypi")
@click.pass_context
def analyze(ctx, diff_file, json_output, model, package, old_version, new_version, ecosystem):
    """Analyze an existing diff file."""
    config = ctx.obj["config"]
    if model:
        config.llm.model = model
    asyncio.run(_analyze(config, diff_file, json_output, package, old_version, new_version, ecosystem))


async def _analyze(config, diff_file, json_output, package, old_version, new_version, ecosystem):
    from depvet.differ.chunker import DiffChunker, DiffFile
    from depvet.analyzer.deep import DeepAnalyzer
    from depvet.alert.stdout import StdoutAlert
    from depvet.models.alert import AlertEvent
    from depvet.models.package import Release
    from depvet.models.verdict import DiffStats
    from datetime import datetime, timezone

    content = Path(diff_file).read_text(encoding="utf-8")
    # Wrap the whole file as a single diff chunk
    chunker = DiffChunker(max_tokens=config.diff.max_chunk_tokens)
    diff_file_obj = DiffFile(path=diff_file, content=content)
    chunks = chunker.chunk([diff_file_obj])

    stats = DiffStats(files_changed=1, lines_added=0, lines_removed=0)
    analyzer = _get_analyzer(config)
    deep = DeepAnalyzer(analyzer)

    verdict = await deep.analyze(
        chunks=chunks,
        package_name=package,
        old_version=old_version,
        new_version=new_version,
        ecosystem=ecosystem,
        diff_stats=stats,
    )

    release = Release(
        name=package, version=new_version, ecosystem=ecosystem,
        previous_version=old_version,
        published_at=datetime.now(timezone.utc).isoformat(),
        url="",
    )
    event = AlertEvent(release=release, verdict=verdict)
    alerter = StdoutAlert()
    alerter.send(event)


# ─────────────────────────────────────────────────────────────
# depvet monitor
# ─────────────────────────────────────────────────────────────

@cli.command()
@click.option("--top", default=0, type=int, help="Monitor top N packages")
@click.option("--sbom", type=click.Path(), default=None, help="SBOM file for watchlist")
@click.option("--interval", default=300, type=int, help="Polling interval in seconds")
@click.option("--once", is_flag=True, help="Run once and exit")
@click.option("--no-npm", is_flag=True, help="Skip npm monitoring")
@click.option("--no-pypi", is_flag=True, help="Skip PyPI monitoring")
@click.option("--no-analyze", is_flag=True, help="Skip LLM analysis (report releases only)")
@click.option("--slack", is_flag=True, help="Enable Slack alerts")
@click.pass_context
def monitor(ctx, top, sbom, interval, once, no_npm, no_pypi, no_analyze, slack):
    """Monitor package registries for new releases."""
    config = ctx.obj["config"]
    asyncio.run(_monitor(config, top, sbom, interval, once, no_npm, no_pypi, no_analyze, slack))


async def _monitor(config, top, sbom, interval, once, no_npm, no_pypi, no_analyze, slack):
    from depvet.registry.pypi import PyPIMonitor
    from depvet.registry.npm import NpmMonitor
    from depvet.registry.state import PollingState
    from depvet.watchlist.manager import WatchlistManager
    from depvet.alert.router import AlertRouter
    from depvet.analyzer.triage import TriageAnalyzer
    from depvet.analyzer.deep import DeepAnalyzer
    from depvet.models.alert import AlertEvent

    state = PollingState(config.state.path)
    wl = WatchlistManager()

    if sbom:
        count = wl.import_from_sbom(sbom)
        click.echo(f"📋 Imported {count} packages from SBOM")

    monitors = []
    if not no_pypi:
        monitors.append(PyPIMonitor())
    if not no_npm:
        monitors.append(NpmMonitor())

    if not monitors:
        click.echo("❌ No ecosystems enabled", err=True)
        sys.exit(1)

    # Load top-N watchlist
    if top > 0:
        for mon in monitors:
            click.echo(f"  Loading top-{top} {mon.ecosystem} packages...")
            pkgs = await mon.load_top_n(top)
            for p in pkgs:
                wl.add(p, mon.ecosystem)
            click.echo(f"  → {len(pkgs)} packages added")

    # Alert router
    slack_webhook = os.environ.get(config.alert.slack_webhook_env) if slack else None
    router = AlertRouter(
        min_severity=config.alert.min_severity,
        slack_webhook=slack_webhook,
    )

    analyzer = _get_analyzer(config) if not no_analyze else None

    click.echo(f"🚀 Starting monitor (interval={interval}s, ecosystems={[m.ecosystem for m in monitors]})")
    click.echo(f"   Watchlist: {wl.stats()}")

    while True:
        for mon in monitors:
            eco = mon.ecosystem
            watchlist_set = wl.as_set(eco)
            if not watchlist_set:
                continue

            since = state.get(eco)
            releases, new_state = await mon.get_new_releases(watchlist_set, since)
            state.set(eco, new_state)

            if releases:
                click.echo(f"  [{eco}] {len(releases)} new release(s)")

            for release in releases:
                click.echo(f"    📦 {release.name} {release.version}")
                if no_analyze:
                    continue

                # Download & analyze
                try:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        tmp = Path(tmpdir)
                        from depvet.differ.downloader import download_package
                        from depvet.differ.unpacker import unpack
                        from depvet.differ.diff_generator import generate_diff

                        if not release.previous_version:
                            continue

                        (tmp / "old").mkdir()
                        (tmp / "new").mkdir()
                        old_arch = await download_package(release.name, release.previous_version, eco, tmp / "old")
                        new_arch = await download_package(release.name, release.version, eco, tmp / "new")
                        if not old_arch or not new_arch:
                            continue

                        old_dir = unpack(old_arch, tmp / "uo")
                        new_dir = unpack(new_arch, tmp / "un")
                        chunks, stats = generate_diff(old_dir, new_dir)

                        if not chunks:
                            continue

                        triage = TriageAnalyzer(analyzer)
                        should, reason, _rule_matches = await triage.should_analyze(
                            chunks, release.name, release.previous_version, release.version
                        )
                        if not should:
                            continue

                        deep = DeepAnalyzer(analyzer)
                        verdict = await deep.analyze(
                            chunks=chunks,
                            package_name=release.name,
                            old_version=release.previous_version,
                            new_version=release.version,
                            ecosystem=eco,
                            diff_stats=stats,
                        )

                        event = AlertEvent(release=release, verdict=verdict)
                        await router.dispatch(event)

                except Exception as e:
                    logger.error(f"Analysis failed for {release.name}: {e}")

        if once:
            break

        click.echo(f"  💤 Sleeping {interval}s...")
        await asyncio.sleep(interval)


# ─────────────────────────────────────────────────────────────
# depvet validate
# ─────────────────────────────────────────────────────────────

@cli.command()
@click.option("--sbom", type=click.Path(exists=True), required=True)
@click.option("--format", "fmt", default="cyclonedx", type=click.Choice(["cyclonedx", "spdx"]))
@click.option("--osv/--no-osv", default=True, help="Check OSV.dev (online)")
@click.option("--json", "json_output", is_flag=True)
@click.pass_context
def validate(ctx, sbom, fmt, osv, json_output):
    """Validate a SBOM against known malicious releases."""
    asyncio.run(_validate(sbom, osv, json_output))


async def _validate(sbom_path, check_osv, json_output):
    from depvet.watchlist.sbom import SBOMParser
    from depvet.known_bad.database import KnownBadDB
    from depvet.known_bad.osv import OSVChecker

    parser = SBOMParser()
    entries = parser.parse(sbom_path)
    click.echo(f"📋 Parsed {len(entries)} packages from SBOM")

    if not entries:
        click.echo("⚠️  No packages found in SBOM")
        return

    # Check local known-bad DB
    db = KnownBadDB()
    local_hits = []
    for entry in entries:
        hit = db.lookup(entry.name, entry.current_version, entry.ecosystem)
        if hit:
            local_hits.append(hit)

    # Check OSV.dev
    osv_hits = {}
    if check_osv:
        click.echo(f"🔍 Checking {len(entries)} packages against OSV.dev...")
        checker = OSVChecker()
        pkg_list = [(e.name, e.current_version, e.ecosystem) for e in entries if e.current_version]
        if pkg_list:
            osv_hits = await checker.batch_check(pkg_list)

    # Report
    total_issues = len(local_hits) + sum(len(v) for v in osv_hits.values())

    if json_output:
        import json as _json
        results = {
            "total_packages": len(entries),
            "issues_found": total_issues,
            "local_db_hits": [{"name": h.name, "version": h.version, "ecosystem": h.ecosystem,
                               "verdict": h.verdict, "severity": h.severity, "summary": h.summary}
                              for h in local_hits],
            "osv_hits": [{"name": h.name, "version": h.version, "ecosystem": h.ecosystem,
                          "osv_id": h.osv_id, "severity": h.severity, "summary": h.summary}
                         for hits in osv_hits.values() for h in hits],
        }
        click.echo(_json.dumps(results, indent=2, ensure_ascii=False))
        return

    if not total_issues:
        click.echo(f"✅ No known threats found in {len(entries)} packages")
        return

    click.echo(f"\n🚨 Found {total_issues} issue(s):\n")

    for hit in local_hits:
        severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(hit.severity, "🔵")
        click.echo(f"  {severity_icon} [{hit.verdict}] {hit.ecosystem}/{hit.name}@{hit.version}")
        click.echo(f"     {hit.summary}")
        if hit.cve:
            click.echo(f"     CVE: {hit.cve}")

    for key, hits in osv_hits.items():
        for hit in hits:
            severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(hit.severity, "🔵")
            click.echo(f"  {severity_icon} [OSV:{hit.osv_id}] {hit.ecosystem}/{hit.name}@{hit.version}")
            click.echo(f"     {hit.summary}")


# ─────────────────────────────────────────────────────────────
# depvet watchlist
# ─────────────────────────────────────────────────────────────

@cli.group()
@click.pass_context
def watchlist(ctx):
    """Manage the watchlist."""
    pass


@watchlist.command("import")
@click.argument("sbom_path", type=click.Path(exists=True))
@click.pass_context
def watchlist_import(ctx, sbom_path):
    """Import packages from a SBOM file."""
    from depvet.watchlist.manager import WatchlistManager
    wl = WatchlistManager()
    count = wl.import_from_sbom(sbom_path)
    click.echo(f"✅ Imported {count} packages from {sbom_path}")


@watchlist.command("add")
@click.argument("name")
@click.option("--ecosystem", "-e", default="pypi", type=click.Choice(["pypi", "npm", "go", "cargo"]))
@click.pass_context
def watchlist_add(ctx, name, ecosystem):
    """Add a package to the watchlist."""
    from depvet.watchlist.manager import WatchlistManager
    wl = WatchlistManager()
    wl.add(name, ecosystem)
    click.echo(f"✅ Added {ecosystem}/{name}")


@watchlist.command("remove")
@click.argument("name")
@click.option("--ecosystem", "-e", default="pypi", type=click.Choice(["pypi", "npm", "go", "cargo"]))
@click.pass_context
def watchlist_remove(ctx, name, ecosystem):
    """Remove a package from the watchlist."""
    from depvet.watchlist.manager import WatchlistManager
    wl = WatchlistManager()
    removed = wl.remove(name, ecosystem)
    if removed:
        click.echo(f"✅ Removed {ecosystem}/{name}")
    else:
        click.echo(f"⚠️  {ecosystem}/{name} not found in watchlist")


@watchlist.command("list")
@click.option("--ecosystem", "-e", default=None)
@click.pass_context
def watchlist_list(ctx, ecosystem):
    """List watchlist packages."""
    from depvet.watchlist.manager import WatchlistManager
    wl = WatchlistManager()
    entries = wl.all_entries()
    if ecosystem:
        entries = [e for e in entries if e.ecosystem == ecosystem]

    if not entries:
        click.echo("(empty watchlist)")
        return

    if _RICH and console:
        table = Table(title=f"Watchlist ({len(entries)} packages)")
        table.add_column("Package", style="cyan")
        table.add_column("Ecosystem", style="green")
        for e in sorted(entries, key=lambda x: (x.ecosystem, x.name)):
            table.add_row(e.name, e.ecosystem)
        console.print(table)
    else:
        for e in sorted(entries, key=lambda x: (x.ecosystem, x.name)):
            click.echo(f"  {e.ecosystem:8s}  {e.name}")


@watchlist.command("stats")
@click.pass_context
def watchlist_stats(ctx):
    """Show watchlist statistics."""
    from depvet.watchlist.manager import WatchlistManager
    wl = WatchlistManager()
    s = wl.stats()
    click.echo(f"Total packages: {s['total']}")
    for eco, count in sorted(s["by_ecosystem"].items()):
        click.echo(f"  {eco}: {count}")


if __name__ == "__main__":
    cli()
