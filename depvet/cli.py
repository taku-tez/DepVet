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


def _setup_logging(verbose: bool, log_format: str = "text") -> None:
    from depvet.logging import setup_logging

    setup_logging(verbose, log_format)


def _get_analyzer(config):
    """Create analyzer from config.

    Supported providers (config llm.provider or DEPVET_LLM_PROVIDER env):
      anthropic / claude — Anthropic API (default)
      openai             — OpenAI API (GPT-4o / GPT-4o-mini)
      vertex-claude      — Claude on Vertex AI (requires VERTEX_PROJECT_ID)
      vertex-gemini      — Gemini on Vertex AI (requires VERTEX_PROJECT_ID)
    """
    from depvet.analyzer.claude import ClaudeAnalyzer
    from depvet.analyzer.openai import OpenAIAnalyzer
    from depvet.analyzer.vertexai import VertexClaudeAnalyzer, VertexGeminiAnalyzer

    provider = config.llm.provider.lower()
    api_key = os.environ.get(config.llm.api_key_env)

    if provider == "openai":
        return OpenAIAnalyzer(
            model=config.llm.model,
            triage_model=config.llm.triage_model,
            api_key=api_key,
            max_tokens=config.llm.max_tokens,
        )
    elif provider in ("vertex-claude", "vertexai-claude", "vertex_claude"):
        return VertexClaudeAnalyzer(
            model=config.llm.model or VertexClaudeAnalyzer.DEFAULT_MODEL,
            triage_model=config.llm.triage_model or VertexClaudeAnalyzer.DEFAULT_TRIAGE_MODEL,
            project_id=os.environ.get("VERTEX_PROJECT_ID"),
            region=os.environ.get("VERTEX_REGION"),
            max_tokens=config.llm.max_tokens,
        )
    elif provider in ("vertex-gemini", "vertexai-gemini", "vertex_gemini", "gemini"):
        return VertexGeminiAnalyzer(
            model=config.llm.model or VertexGeminiAnalyzer.DEFAULT_MODEL,
            triage_model=config.llm.triage_model or VertexGeminiAnalyzer.DEFAULT_TRIAGE_MODEL,
            project_id=os.environ.get("VERTEX_PROJECT_ID"),
            region=os.environ.get("VERTEX_REGION"),
            max_tokens=config.llm.max_tokens,
        )
    else:
        # Default: Anthropic direct API
        return ClaudeAnalyzer(
            model=config.llm.model,
            triage_model=config.llm.triage_model,
            api_key=api_key,
            max_tokens=config.llm.max_tokens,
        )


def _build_release_url(name: str, version: str, ecosystem: str) -> str:
    """Build registry URL for a package release."""
    if ecosystem == "pypi":
        return f"https://pypi.org/project/{name}/{version}/"
    elif ecosystem == "go":
        return f"https://pkg.go.dev/{name}@{version}"
    elif ecosystem == "cargo":
        return f"https://crates.io/crates/{name}/{version}"
    else:  # npm + default
        return f"https://www.npmjs.com/package/{name}/v/{version}"


@click.group()
@click.version_option(__version__, prog_name="depvet")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--config", "-c", type=click.Path(), default=None, help="Path to depvet.toml")
@click.option(
    "--log-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Log output format (text or json)",
)
@click.pass_context
def cli(ctx: click.Context, verbose: bool, config: Optional[str], log_format: str) -> None:
    """DepVet — Software supply chain monitoring engine."""
    _setup_logging(verbose, log_format)
    ctx.ensure_object(dict)
    from depvet.config.config import load_config

    ctx.obj["config"] = load_config(config)


# ─────────────────────────────────────────────────────────────
# depvet scan
# ─────────────────────────────────────────────────────────────


@cli.command()
@click.argument("package", metavar="PACKAGE", type=str)
@click.argument("old_version", metavar="OLD_VERSION", type=str)
@click.argument("new_version", metavar="NEW_VERSION", type=str)
@click.option("--npm", "ecosystem", flag_value="npm", help="Use npm ecosystem")
@click.option("--pypi", "ecosystem", flag_value="pypi", default=True, help="Use PyPI (default)")
@click.option("--go", "ecosystem", flag_value="go", help="Use Go modules ecosystem")
@click.option("--cargo", "ecosystem", flag_value="cargo", help="Use Cargo (Rust) ecosystem")
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
    from depvet.alert.stdout import StdoutAlerter
    from depvet.models.alert import AlertEvent
    from depvet.models.package import Release
    from datetime import datetime, timezone

    click.echo(f"🔍 Scanning {ecosystem}/{package}: {old_version} → {new_version}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        click.echo("  Downloading packages...")
        (tmp / "old").mkdir(parents=True, exist_ok=True)
        (tmp / "new").mkdir(parents=True, exist_ok=True)
        old_archive = await download_package(package, old_version, ecosystem, tmp / "old")
        new_archive = await download_package(package, new_version, ecosystem, tmp / "new")

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

        click.echo(
            f"  Diff: {stats.files_changed} files changed (+{stats.lines_added}/-{stats.lines_removed} lines), {len(chunks)} chunk(s)"
        )

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
            url=_build_release_url(package, new_version, ecosystem),
        )
        event = AlertEvent(release=release, verdict=verdict)

        alerter = StdoutAlerter(json_mode=json_output, min_severity="NONE")  # scan always outputs
        await alerter.send(event)


# ─────────────────────────────────────────────────────────────
# depvet diff
# ─────────────────────────────────────────────────────────────


@cli.command()
@click.argument("package", metavar="PACKAGE", type=str)
@click.argument("old_version", metavar="OLD_VERSION", type=str)
@click.argument("new_version", metavar="NEW_VERSION", type=str)
@click.option("--npm", "ecosystem", flag_value="npm", help="Use npm ecosystem")
@click.option("--pypi", "ecosystem", flag_value="pypi", default=True, help="Use PyPI (default)")
@click.option("--go", "ecosystem", flag_value="go", help="Use Go modules ecosystem")
@click.option("--cargo", "ecosystem", flag_value="cargo", help="Use Cargo (Rust) ecosystem")
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
    from depvet.alert.stdout import StdoutAlerter
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
        name=package,
        version=new_version,
        ecosystem=ecosystem,
        previous_version=old_version,
        published_at=datetime.now(timezone.utc).isoformat(),
        url="",
    )
    event = AlertEvent(release=release, verdict=verdict)
    alerter = StdoutAlerter(json_mode=json_output, min_severity="NONE")  # analyze always outputs
    await alerter.send(event)


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
@click.option("--model", default=None, help="Override LLM model")
@click.option("--json", "json_output", is_flag=True, help="Output alerts as JSON")
@click.pass_context
def monitor(ctx, top, sbom, interval, once, no_npm, no_pypi, no_analyze, slack, model, json_output):
    """Monitor package registries for new releases."""
    config = ctx.obj["config"]
    if model:
        config.llm.model = model
    # CLI flag overrides config; config provides the default
    effective_interval = interval if interval != 300 else config.monitor.interval
    # top=0 means "use config defaults" — pass 0 so _monitor can use per-ecosystem config values
    asyncio.run(_monitor(config, top, sbom, effective_interval, once, no_npm, no_pypi, no_analyze, slack, json_output))


async def _preflight_checks(config, no_analyze: bool, slack: bool, sbom) -> None:
    """Validate runtime environment before entering the monitor loop.

    Raises SystemExit on hard errors; logs warnings for soft issues.
    """
    import aiohttp

    errors: list[str] = []
    warnings: list[str] = []

    # 1. LLM API key
    if not no_analyze:
        provider = config.llm.provider.lower()
        if provider in ("claude", "anthropic"):
            if not os.environ.get(config.llm.api_key_env):
                errors.append(f"LLM API key not set: export {config.llm.api_key_env}")
        elif provider == "openai":
            if not os.environ.get(config.llm.api_key_env) and not os.environ.get("OPENAI_API_KEY"):
                errors.append(f"OpenAI API key not set: export {config.llm.api_key_env} or OPENAI_API_KEY")
        elif provider.startswith("vertex"):
            if not os.environ.get("VERTEX_PROJECT_ID"):
                errors.append("VERTEX_PROJECT_ID not set for Vertex AI provider")

    # 2. Slack webhook
    if slack:
        url = os.environ.get(config.alert.slack_webhook_env)
        if not url:
            errors.append(f"Slack webhook not set: export {config.alert.slack_webhook_env}")

    # 3. Webhook URL reachability
    if config.alert.webhook_url:
        try:
            async with aiohttp.ClientSession() as session:
                resp = await session.head(
                    config.alert.webhook_url,
                    timeout=aiohttp.ClientTimeout(total=5),
                )
                if resp.status >= 500:
                    warnings.append(f"Webhook URL returned {resp.status}: {config.alert.webhook_url}")
        except Exception as e:
            warnings.append(f"Webhook URL unreachable: {config.alert.webhook_url} ({e})")

    # 4. SBOM file existence
    if sbom and not Path(sbom).exists():
        errors.append(f"SBOM file not found: {sbom}")

    # 5. State file writability
    state_path = Path(config.state.path)
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        with open(state_path, "a"):
            pass
    except OSError as e:
        errors.append(f"State file not writable: {state_path} ({e})")

    # Report
    for w in warnings:
        logger.warning(w)
        click.echo(f"  ⚠️  {w}", err=True)

    if errors:
        for err_msg in errors:
            logger.error(err_msg)
            click.echo(f"  ❌ {err_msg}", err=True)
        click.echo("\nPre-flight checks failed. Fix the errors above and retry.", err=True)
        sys.exit(1)

    if not warnings:
        click.echo("  ✅ Pre-flight checks passed")


async def _monitor(config, top, sbom, interval, once, no_npm, no_pypi, no_analyze, slack, json_output=False):
    import signal
    import time as _time

    from depvet.registry.pypi import PyPIMonitor
    from depvet.registry.npm import NpmMonitor
    from depvet.registry.go import GoModulesMonitor
    from depvet.registry.cargo import CargoMonitor
    from depvet.registry.maven import MavenMonitor
    from depvet.registry.state import PollingState
    from depvet.watchlist.manager import WatchlistManager
    from depvet.alert.router import AlertRouter
    from depvet.alert.stdout import StdoutAlerter
    from depvet.alert.slack import SlackAlerter
    from depvet.alert.webhook import WebhookAlerter
    from depvet.alert.dlq import DeadLetterQueue
    from depvet.analyzer.triage import TriageAnalyzer
    from depvet.analyzer.deep import DeepAnalyzer

    # --- Pre-flight checks ---
    await _preflight_checks(config, no_analyze, slack, sbom)

    # --- Graceful shutdown setup ---
    shutdown_event = asyncio.Event()
    releases_processed = 0
    cycles_completed = 0
    start_time = _time.monotonic()

    def _request_shutdown(signame: str) -> None:
        logger.info("Received %s, initiating graceful shutdown...", signame, extra={"signal": signame})
        click.echo(f"\n  🛑 Received {signame}, finishing current batch...")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, _request_shutdown, sig.name)
    except NotImplementedError:
        # Windows: only SIGINT via Ctrl+C
        signal.signal(signal.SIGINT, lambda *_: _request_shutdown("SIGINT"))

    state = PollingState(config.state.path)
    wl = WatchlistManager()
    dlq = DeadLetterQueue(path=config.alert.dlq_path)

    # Resolve watchlist sources: 'sbom' source needed for config sbom_path auto-import
    # CLI --sbom always overrides; config.watchlist.sbom_path only used if 'sbom' in sources
    effective_sbom = sbom  # CLI --sbom takes priority
    if not effective_sbom and "sbom" in config.watchlist.sources and config.watchlist.sbom_path:
        effective_sbom = config.watchlist.sbom_path
    if effective_sbom:
        sbom_fmt = getattr(config.watchlist, "sbom_format", None)
        count = wl.import_from_sbom(effective_sbom, fmt=sbom_fmt if sbom_fmt != "cyclonedx" else None)
        click.echo(f"📋 Imported {count} packages from SBOM ({effective_sbom})")

    # Build monitor list from config.monitor.ecosystems + CLI flags
    active_ecosystems = set(config.monitor.ecosystems)
    monitors = []
    if "pypi" in active_ecosystems and not no_pypi:
        monitors.append(PyPIMonitor())
    if "npm" in active_ecosystems and not no_npm:
        monitors.append(NpmMonitor())
    if "go" in active_ecosystems:
        monitors.append(GoModulesMonitor())
    if "cargo" in active_ecosystems:
        monitors.append(CargoMonitor())
    if "maven" in active_ecosystems:
        click.echo(
            "⚠️  Maven monitoring tracks releases but scan/diff/download is not yet supported.",
            err=True,
        )
        monitors.append(MavenMonitor())

    if not monitors:
        click.echo("❌ No ecosystems enabled", err=True)
        sys.exit(1)

    # Resolve watchlist sources from config.watchlist.sources
    # sources: ["top_n"] | ["sbom"] | ["explicit"] | any combination
    active_sources = config.watchlist.sources  # e.g. ["top_n", "sbom"]

    # Load top-N watchlist (ephemeral — does NOT persist to .depvet_watchlist.yaml)
    ephemeral_top: dict[str, set[str]] = {}  # ecosystem -> set of package names
    _last_top_n_refresh = 0.0  # timestamp of last top-N refresh
    refresh_interval = config.watchlist.refresh_interval  # seconds between top-N refreshes

    async def _refresh_top_n() -> None:
        """Load/reload top-N packages from registries into ephemeral_top."""
        for mon in monitors:
            eco = mon.ecosystem
            if top > 0:
                n = top
            elif eco == "npm":
                n = config.watchlist.top_n_npm
            else:
                n = config.watchlist.top_n_pypi
            if n > 0 and "top_n" in active_sources:
                click.echo(f"  Loading top-{n} {eco} packages (ephemeral)...")
                pkgs = await mon.load_top_n(n)
                ephemeral_top[eco] = set(pkgs)
                click.echo(f"  → {len(pkgs)} packages added to ephemeral set")

    # Initial load if top_n is an active source or --top was passed
    if top > 0 or "top_n" in active_sources:
        await _refresh_top_n()
        _last_top_n_refresh = _time.monotonic()

    # Alert router
    router = AlertRouter(min_severity=config.alert.min_severity, dlq=dlq)
    router.register(StdoutAlerter(json_mode=json_output))
    if slack:
        slack_webhook = os.environ.get(config.alert.slack_webhook_env)
        router.register(SlackAlerter(webhook_url=slack_webhook))
    if config.alert.webhook_url:
        router.register(
            WebhookAlerter(
                url=config.alert.webhook_url,
                secret_env=config.alert.webhook_secret_env,
            )
        )

    analyzer = _get_analyzer(config) if not no_analyze else None
    # Semaphore: limits max concurrent analyses
    _sem = asyncio.Semaphore(config.monitor.max_concurrent_analyses)
    # queue_max_size: max releases to process per poll cycle (0 = unlimited)
    _batch_limit = config.monitor.queue_max_size  # renamed for clarity

    click.echo(f"🚀 Starting monitor (interval={interval}s, ecosystems={[m.ecosystem for m in monitors]})")
    click.echo(f"   Watchlist: {wl.stats()}")

    while not shutdown_event.is_set():
        # Refresh top-N if refresh_interval has elapsed
        if refresh_interval > 0 and (top > 0 or "top_n" in active_sources):
            if _time.monotonic() - _last_top_n_refresh >= refresh_interval:
                click.echo("  🔄 Refreshing top-N watchlist...")
                await _refresh_top_n()
                _last_top_n_refresh = _time.monotonic()

        for mon in monitors:
            eco = mon.ecosystem
            # Build watchlist according to active sources
            # 'explicit': use persisted watchlist; 'top_n': use ephemeral top-N
            # If sources is empty or contains 'explicit', always include explicit entries
            use_explicit = not config.watchlist.sources or "explicit" in config.watchlist.sources
            explicit_set = wl.as_set(eco) if use_explicit else set()
            watchlist_set = explicit_set | ephemeral_top.get(eco, set())
            if not watchlist_set:
                continue

            since = state.get(eco)
            releases, new_state = await mon.get_new_releases(watchlist_set, since)
            # NOTE: state.set() is deferred until after processing to avoid
            # losing releases when batch is truncated by queue_max_size.

            if releases:
                click.echo(f"  [{eco}] {len(releases)} new release(s)")

            async def _process_one(release, _eco=eco):
                nonlocal releases_processed
                click.echo(f"    📦 {release.name} {release.version}")
                if no_analyze or not release.previous_version:
                    # Release-only notification: dispatch to alert backends without LLM analysis
                    from depvet.models.alert import AlertEvent
                    from depvet.models.verdict import Verdict, VerdictType, Severity, DiffStats
                    from datetime import datetime, timezone

                    notify_verdict = Verdict(
                        verdict=VerdictType.UNKNOWN,
                        severity=Severity.MEDIUM,  # visible by default min_severity
                        confidence=0.0,
                        summary=(
                            "新規リリースを検出（LLM解析はスキップ）"
                            if no_analyze
                            else "新規パッケージの初回リリースを検出（差分比較不可）"
                        ),
                        findings=[],
                        analysis_duration_ms=0,
                        diff_stats=DiffStats(files_changed=0, lines_added=0, lines_removed=0),
                        model="none",
                        analyzed_at=datetime.now(timezone.utc).isoformat(),
                        chunks_analyzed=0,
                        tokens_used=0,
                    )
                    notify_event = AlertEvent(release=release, verdict=notify_verdict)
                    await router.dispatch(notify_event)
                    return
                try:
                    async with _sem:
                        with tempfile.TemporaryDirectory() as tmpdir:
                            tmp = Path(tmpdir)
                            from depvet.differ.downloader import download_package
                            from depvet.differ.unpacker import unpack
                            from depvet.differ.diff_generator import generate_diff

                            (tmp / "old").mkdir()
                            (tmp / "new").mkdir()
                            old_arch = await download_package(release.name, release.previous_version, _eco, tmp / "old")
                            new_arch = await download_package(release.name, release.version, _eco, tmp / "new")
                            if not old_arch or not new_arch:
                                return

                            old_dir = unpack(old_arch, tmp / "uo")
                            new_dir = unpack(new_arch, tmp / "un")
                            chunks, stats = generate_diff(old_dir, new_dir)

                            if not chunks:
                                return

                            triage = TriageAnalyzer(analyzer)
                            should, reason, rule_matches = await triage.should_analyze(
                                chunks, release.name, release.previous_version, release.version
                            )
                            if not should:
                                return

                            # Fetch version transition context (same as scan path)
                            from depvet.analyzer.version_signal import get_transition_context

                            version_ctx = await get_transition_context(
                                release.name,
                                release.previous_version,
                                release.version,
                                _eco,
                            )

                            deep = DeepAnalyzer(analyzer)
                            verdict = await deep.analyze(
                                chunks=chunks,
                                package_name=release.name,
                                old_version=release.previous_version,
                                new_version=release.version,
                                ecosystem=_eco,
                                diff_stats=stats,
                                rule_matches=rule_matches,
                                version_context=version_ctx,
                            )

                            event = AlertEvent(release=release, verdict=verdict)
                            await router.dispatch(event)
                    releases_processed += 1
                except Exception as e:
                    logger.error(f"Analysis failed for {release.name}: {e}")

            if releases:
                # Apply batch limit: process at most _batch_limit releases per cycle
                # (0 = unlimited).  Truncated releases are NOT lost — state is only
                # advanced when all releases are consumed, so overflow releases will
                # be re-fetched on the next poll cycle.
                truncated = 0 < _batch_limit < len(releases)
                batch = releases if _batch_limit <= 0 else releases[:_batch_limit]
                if truncated:
                    click.echo(
                        f"  ⚠️  [{eco}] {len(releases)} releases exceed "
                        f"queue_max_size={_batch_limit}; processing {len(batch)}, "
                        f"remaining {len(releases) - len(batch)} deferred to next cycle"
                    )
                tasks = [asyncio.create_task(_process_one(r)) for r in batch]
                await asyncio.gather(*tasks)

            # Only advance polling state when the full batch was consumed.
            # If truncated, keep the old state so overflow releases are
            # re-fetched on the next poll cycle.
            if not releases or not (0 < _batch_limit < len(releases)):
                state.set(eco, new_state)

        cycles_completed += 1

        if once:
            break

        click.echo(f"  💤 Sleeping {interval}s...")
        try:
            await asyncio.wait_for(shutdown_event.wait(), timeout=interval)
            break  # shutdown requested during sleep
        except asyncio.TimeoutError:
            pass  # normal: interval elapsed

    # --- Shutdown summary ---
    elapsed = _time.monotonic() - start_time
    dlq_pending = dlq.count()
    click.echo(
        f"\n  ✅ Shutdown: {releases_processed} releases processed, "
        f"{router.dispatched_count} alerts sent, {cycles_completed} cycle(s) in {elapsed:.0f}s"
    )
    if dlq_pending:
        click.echo(f"  ⚠️  DLQ has {dlq_pending} pending entries (run `depvet dlq list`)")


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
    asyncio.run(_validate(sbom, fmt, osv, json_output))


async def _validate(sbom_path, sbom_format, check_osv, json_output):
    from depvet.watchlist.sbom import SBOMParser
    from depvet.known_bad.database import KnownBadDB
    from depvet.known_bad.osv import OSVChecker

    parser = SBOMParser()
    entries = parser.parse(sbom_path, fmt=sbom_format)
    click.echo(f"📋 Parsed {len(entries)} packages from SBOM (format={sbom_format})")

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
            "local_db_hits": [
                {
                    "name": h.name,
                    "version": h.version,
                    "ecosystem": h.ecosystem,
                    "verdict": h.verdict,
                    "severity": h.severity,
                    "summary": h.summary,
                }
                for h in local_hits
            ],
            "osv_hits": [
                {
                    "name": h.name,
                    "version": h.version,
                    "ecosystem": h.ecosystem,
                    "osv_id": h.osv_id,
                    "severity": h.severity,
                    "summary": h.summary,
                }
                for hits in osv_hits.values()
                for h in hits
            ],
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
# depvet config
# ─────────────────────────────────────────────────────────────


@cli.group("config")
@click.pass_context
def config_group(ctx):
    """View configuration."""
    pass


@config_group.command("show")
@click.pass_context
def config_show(ctx):
    """Display the active configuration."""
    config = ctx.obj["config"]
    sections = {
        "llm": config.llm,
        "monitor": config.monitor,
        "watchlist": config.watchlist,
        "diff": config.diff,
        "alert": config.alert,
        "state": config.state,
        "securify": config.securify,
    }
    for name, section in sections.items():
        click.echo(f"[{name}]")
        for key, value in section.model_dump().items():
            click.echo(f"  {key} = {value!r}")
        click.echo()


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
@click.option("--ecosystem", "-e", default="pypi", type=click.Choice(["pypi", "npm", "go", "cargo", "maven"]))
@click.pass_context
def watchlist_add(ctx, name, ecosystem):
    """Add a package to the watchlist."""
    if ecosystem == "maven":
        click.echo(
            "⚠️  Maven is supported for SBOM import and watchlist tracking, "
            "but scan/diff/download is not yet implemented.",
            err=True,
        )
    from depvet.watchlist.manager import WatchlistManager

    wl = WatchlistManager()
    wl.add(name, ecosystem)
    click.echo(f"✅ Added {ecosystem}/{name}")


@watchlist.command("remove")
@click.argument("name")
@click.option("--ecosystem", "-e", default="pypi", type=click.Choice(["pypi", "npm", "go", "cargo", "maven"]))
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


# ─────────────────────────────────────────────────────────────
# depvet dlq
# ─────────────────────────────────────────────────────────────


@cli.group()
@click.pass_context
def dlq(ctx):
    """Manage the dead letter queue for failed alerts."""
    pass


@dlq.command("list")
@click.pass_context
def dlq_list(ctx):
    """List pending DLQ entries."""
    from depvet.alert.dlq import DeadLetterQueue

    config = ctx.obj["config"]
    q = DeadLetterQueue(path=config.alert.dlq_path)
    entries = q.list_entries()
    if not entries:
        click.echo("DLQ is empty.")
        return
    for e in entries:
        ev = e.get("event_data", {})
        rel = ev.get("release", {})
        click.echo(
            f"  [{e.get('timestamp', '?')[:19]}] "
            f"{e.get('alerter_type', '?')} — "
            f"{rel.get('ecosystem', '?')}/{rel.get('name', '?')}@{rel.get('version', '?')} "
            f"({e.get('error_message', '')[:60]})"
        )
    click.echo(f"\n  Total: {len(entries)} entries")


@dlq.command("count")
@click.pass_context
def dlq_count(ctx):
    """Show number of DLQ entries."""
    from depvet.alert.dlq import DeadLetterQueue

    config = ctx.obj["config"]
    q = DeadLetterQueue(path=config.alert.dlq_path)
    click.echo(f"DLQ entries: {q.count()}")


@dlq.command("clear")
@click.pass_context
def dlq_clear(ctx):
    """Clear all DLQ entries."""
    from depvet.alert.dlq import DeadLetterQueue

    config = ctx.obj["config"]
    q = DeadLetterQueue(path=config.alert.dlq_path)
    n = q.clear()
    click.echo(f"Cleared {n} DLQ entries.")


if __name__ == "__main__":
    cli()
