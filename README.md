# DepVet — Dependency Vetter

**Software supply chain monitoring engine.**  
Monitors PyPI/npm registries for new releases and detects malicious code using LLM analysis.

```
Vetシリーズ
├── SpecVet   : API仕様の静的解析・テイント追跡（Auto-Pentest）
└── DepVet    : 依存パッケージのリリース監視・悪意検出（本ツール）
```

## Features

- **Continuous monitoring**: Polls PyPI (XML-RPC) and npm (CouchDB _changes) for new releases
- **3-stage analysis**: Triage (fast/cheap) → Deep analysis (structured verdict) → Context enrichment
- **Structured verdicts**: `MALICIOUS`/`SUSPICIOUS`/`BENIGN`/`UNKNOWN` with severity, confidence, CWE
- **SBOM-aware**: Import CycloneDX/SPDX SBOMs to auto-generate per-project watchlists
- **Multi-LLM**: Claude / OpenAI / local models via plugin
- **Alert routing**: stdout (Rich), Slack, generic webhooks

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

# Monitor top 100 PyPI packages (once)
depvet monitor --top 100 --once

# Monitor from your SBOM
depvet monitor --sbom ./sbom.cyclonedx.json --slack

# Manage watchlist
depvet watchlist add requests --ecosystem pypi
depvet watchlist list
```

## Commands

```bash
depvet scan <package> <old_version> <new_version>   # Scan a version diff
depvet diff <package> <old_version> <new_version>   # Generate diff only
depvet analyze <diff_file>                           # Analyze an existing diff
depvet monitor [options]                             # Continuous monitoring
depvet validate --sbom <file>                        # Validate SBOM against known threats
depvet watchlist import|add|remove|list|stats       # Manage watchlist
```

## Configuration

Copy `depvet.toml.example` to `depvet.toml`:

```toml
[llm]
provider = "claude"
model = "claude-sonnet-4-20250514"
api_key_env = "ANTHROPIC_API_KEY"
triage_model = "claude-haiku-4-5-20251001"

[monitor]
interval = 300
ecosystems = ["pypi", "npm"]

[alert]
min_severity = "MEDIUM"
slack_webhook_env = "DEPVET_SLACK_WEBHOOK"
```

## Output Example

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 MALICIOUS RELEASE DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Package   : requests (PyPI)
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
├── registry/        # PyPI (XML-RPC) + npm (CouchDB) monitors
├── differ/          # Download → Unpack → Diff → Chunk
├── analyzer/        # Stage1: Triage | Stage2: Deep | VerdictMerger
├── watchlist/       # SBOM parser + Top-N + Explicit
├── alert/           # Router → Stdout | Slack | Webhook
└── models/          # Verdict, Finding, Release, AlertEvent
```

## Roadmap

- **Phase 1** ✅ CLI MVP (PyPI + npm + Claude + stdout/Slack)
- **Phase 2** 🔄 SBOM validation, Go/Cargo support, PyPI publish
- **Phase 3** 📋 Securify integration (SKG, Finding, risk propagation)

## License

MIT
