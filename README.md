# DepVet — Dependency Vetter

**Software supply chain monitoring engine.**
Monitors PyPI, npm, Go, Cargo, and Maven registries for new releases and detects malicious code using LLM-powered analysis.

```
Vetシリーズ
├── SpecVet   : API仕様の静的解析・テイント追跡（Auto-Pentest）
└── DepVet    : 依存パッケージのリリース監視・悪意検出（本ツール）
```

## Features

- **5 ecosystems**: PyPI, npm, Go modules, Cargo (Rust), Maven
- **Continuous monitoring**: Polls registries for new releases with retry & exponential backoff
- **3-stage analysis**: Rule-based triage → LLM deep analysis → Version transition signals
- **40+ detection rules**: base64+exec chains, env exfiltration, CommonJS obfuscation, install hooks, DNS tunneling, credential harvesting, sabotage patterns
- **Structured verdicts**: `MALICIOUS` / `SUSPICIOUS` / `BENIGN` / `UNKNOWN` with severity, confidence, CWE
- **SBOM-aware**: Import CycloneDX/SPDX SBOMs to auto-generate per-project watchlists
- **Multi-LLM**: Claude (Anthropic) / OpenAI (GPT-4o) / Vertex AI (Claude & Gemini)
- **Alert routing**: stdout (Rich), Slack webhooks, generic webhooks with HMAC signing
- **Dead Letter Queue**: Failed alerts saved for retry (`depvet dlq`)
- **Operational**: Structured JSON logging, health endpoint, graceful shutdown, pre-flight checks, analysis metrics

## Installation

```bash
pip install depvet
```

Or from source:

```bash
git clone https://github.com/taku-tez/DepVet
cd DepVet
pip install -e ".[dev]"
```

## Quick Start

```bash
# Set your API key
export ANTHROPIC_API_KEY=sk-ant-...

# Scan a specific version bump
depvet scan requests 2.31.0 2.32.0

# Scan across ecosystems
depvet scan lodash 4.17.20 4.17.21 --npm
depvet scan com.google.guava:guava 33.0.0-jre 33.3.1-jre --maven
depvet scan serde 1.0.200 1.0.203 --cargo

# Monitor top 100 PyPI packages (once)
depvet monitor --top 100 --once

# Monitor with Slack alerts and JSON output
depvet monitor --sbom ./sbom.cyclonedx.json --slack --json

# Manage watchlist
depvet watchlist add requests --ecosystem pypi
depvet watchlist add com.google.guava:guava --ecosystem maven
depvet watchlist list
```

## Commands

```bash
# Analysis
depvet scan <pkg> <old> <new> [--pypi|--npm|--go|--cargo|--maven] [--json] [--model MODEL]
depvet diff <pkg> <old> <new> [--pypi|--npm|--go|--cargo|--maven] [-o FILE]
depvet analyze <diff_file> [--json] [--model MODEL]

# Monitoring
depvet monitor [--top N] [--sbom FILE] [--interval N] [--once] [--slack] [--json] [--model MODEL]
depvet validate --sbom <file> [--format cyclonedx|spdx] [--osv|--no-osv] [--json]

# Watchlist
depvet watchlist import <sbom_file>
depvet watchlist add <name> --ecosystem <eco>
depvet watchlist remove <name> --ecosystem <eco>
depvet watchlist list [--ecosystem <eco>]
depvet watchlist stats

# Operations
depvet health [--json]          # Monitor health status
depvet config show              # Display active configuration
depvet dlq list|count|clear     # Dead letter queue management
```

## Configuration

Copy `depvet.toml.example` to `depvet.toml`:

```toml
[llm]
provider = "claude"                      # claude | openai | vertex-claude | vertex-gemini
model = "claude-sonnet-4-20250514"
triage_model = "claude-haiku-4-5-20251001"

[monitor]
interval = 300
ecosystems = ["pypi", "npm", "go", "cargo", "maven"]
max_concurrent_analyses = 4
queue_max_size = 100

[watchlist]
sources = ["explicit", "top_n"]          # explicit | top_n | sbom
sbom_path = "./sbom.cyclonedx.json"
sbom_format = "cyclonedx"                # cyclonedx | spdx

[alert]
min_severity = "MEDIUM"
slack_webhook_env = "DEPVET_SLACK_WEBHOOK"
webhook_url = ""
webhook_secret_env = "DEPVET_WEBHOOK_SECRET"
dlq_path = ".depvet_dlq.yaml"
```

### CLI Options

```bash
depvet --verbose              # Debug logging
depvet --log-format json      # Structured JSON logs (stderr)
depvet -c /path/to/depvet.toml  # Custom config path
```

## Output Example

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 MALICIOUS RELEASE DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Package   : requests (PYPI)
Version   : 2.31.0 → 2.32.0
Verdict   : MALICIOUS
Severity  : CRITICAL
Confidence: 0.97

Findings:
  [1] EXFILTRATION (CWE-200)
      File: requests/auth.py (L42-L67)
      Base64デコードされた文字列が外部IPへの送信に使用されている

Summary:
  新バージョンのrequests/auth.pyにbase64エンコードされたコードが追加され、
  環境変数（AWS_SECRET_ACCESS_KEY等）を103.45.67.89:8080に送信する。

URL: https://pypi.org/project/requests/2.32.0/
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Architecture

```
DepVet CLI
├── registry/        # PyPI (XML-RPC) + npm (CouchDB) + Go (proxy) + Cargo + Maven monitors
├── differ/          # Download → Unpack → Diff → Chunk (all 5 ecosystems)
├── analyzer/        # Rules (40+) → Triage → Deep LLM → Version signals → VerdictMerger
│   ├── rules.py     # Single-line + window-based chain detection
│   ├── ast_scan.py  # Python AST-level malicious pattern detection
│   ├── triage.py    # Stage 1: fast/cheap filtering
│   └── deep.py      # Stage 2: structured LLM analysis
├── watchlist/       # SBOM (CycloneDX/SPDX) + Top-N + Explicit
├── alert/           # Router → Stdout | Slack | Webhook | DLQ
├── known_bad/       # Local DB + OSV.dev API checker
├── health.py        # Health check endpoint
├── metrics.py       # Runtime metrics collection
├── http.py          # Retry with exponential backoff
├── logging.py       # Structured JSON logging
├── exceptions.py    # Domain exception hierarchy
└── models/          # Verdict, Finding, Release, AlertEvent
```

## Docker

```bash
docker build -t depvet .
docker run --rm -e ANTHROPIC_API_KEY=$KEY depvet scan requests 2.31.0 2.32.0

# Long-running monitor with health check
docker run -d --name depvet-monitor \
  -e ANTHROPIC_API_KEY=$KEY \
  --read-only --tmpfs /tmp:size=512m \
  --security-opt no-new-privileges \
  depvet monitor --top 100
```

## Roadmap

- **Phase 1** ✅ CLI MVP (PyPI + npm + Claude + stdout/Slack)
- **Phase 2** ✅ Go/Cargo/Maven support, SBOM validation, operational reliability
- **Phase 3** 📋 Securify integration, PyPI publish, SARIF output

## License

MIT
