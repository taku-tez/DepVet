"""Default configuration values for DepVet."""

DEFAULT_LLM_PROVIDER = "claude"
DEFAULT_LLM_MODEL = "claude-sonnet-4-20250514"
DEFAULT_TRIAGE_MODEL = "claude-haiku-4-5-20251001"
DEFAULT_MAX_TOKENS = 4096
DEFAULT_LLM_TIMEOUT = 60

DEFAULT_MONITOR_INTERVAL = 300
DEFAULT_ECOSYSTEMS = ["pypi", "npm"]
DEFAULT_MAX_CONCURRENT = 4
DEFAULT_QUEUE_MAX_SIZE = 100

DEFAULT_TOP_N_PYPI = 1000
DEFAULT_TOP_N_NPM = 1000
DEFAULT_WATCHLIST_REFRESH_INTERVAL = 86400

DEFAULT_MAX_CHUNK_TOKENS = 8000
DEFAULT_MIN_SEVERITY = "MEDIUM"
DEFAULT_STATE_PATH = "./depvet_state.yaml"

PRIORITY_FILES = [
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "package.json",
    "binding.gyp",
    "__init__.py",
    "index.js",
    "index.ts",
    "main.py",
    "auth.py",
    "http.py",
    "client.py",
    "session.py",
]

SKIP_PATTERNS = [
    "test_*.py",
    "*_test.py",
    "*.test.js",
    "*.spec.js",
    "docs/",
    "examples/",
    "CHANGELOG*",
    "*.md",
    "*.rst",
]
