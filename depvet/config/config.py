"""Configuration management for DepVet using pydantic-settings."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

from pydantic import Field
from pydantic_settings import BaseSettings

from depvet.config.defaults import (
    DEFAULT_ECOSYSTEMS,
    DEFAULT_LLM_MODEL,
    DEFAULT_LLM_PROVIDER,
    DEFAULT_LLM_TIMEOUT,
    DEFAULT_MAX_CHUNK_TOKENS,
    DEFAULT_MAX_CONCURRENT,
    DEFAULT_MAX_TOKENS,
    DEFAULT_MIN_SEVERITY,
    DEFAULT_MONITOR_INTERVAL,
    DEFAULT_QUEUE_MAX_SIZE,
    DEFAULT_STATE_PATH,
    DEFAULT_TOP_N_NPM,
    DEFAULT_TOP_N_PYPI,
    DEFAULT_TRIAGE_MODEL,
    DEFAULT_WATCHLIST_REFRESH_INTERVAL,
    PRIORITY_FILES,
)


class LLMConfig(BaseSettings):
    provider: str = DEFAULT_LLM_PROVIDER
    model: str = DEFAULT_LLM_MODEL
    api_key_env: str = "ANTHROPIC_API_KEY"
    triage_model: str = DEFAULT_TRIAGE_MODEL
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout: int = DEFAULT_LLM_TIMEOUT
    # Vertex AI
    vertex_project_id: Optional[str] = Field(default=None, alias="VERTEX_PROJECT_ID")
    vertex_region: Optional[str] = Field(default="us-east5", alias="VERTEX_REGION")

    model_config = {"env_prefix": "DEPVET_LLM_", "extra": "ignore", "populate_by_name": True}


class MonitorConfig(BaseSettings):
    interval: int = DEFAULT_MONITOR_INTERVAL
    ecosystems: list[str] = Field(default_factory=lambda: DEFAULT_ECOSYSTEMS.copy())
    max_concurrent_analyses: int = DEFAULT_MAX_CONCURRENT
    queue_max_size: int = DEFAULT_QUEUE_MAX_SIZE

    model_config = {"env_prefix": "DEPVET_MONITOR_", "extra": "ignore"}


class WatchlistConfig(BaseSettings):
    sources: list[str] = Field(default_factory=lambda: ["top_n"])
    sbom_path: Optional[str] = None
    sbom_format: str = "cyclonedx"
    top_n_pypi: int = DEFAULT_TOP_N_PYPI
    top_n_npm: int = DEFAULT_TOP_N_NPM
    refresh_interval: int = DEFAULT_WATCHLIST_REFRESH_INTERVAL

    model_config = {"env_prefix": "DEPVET_WATCHLIST_", "extra": "ignore"}


class DiffConfig(BaseSettings):
    max_chunk_tokens: int = DEFAULT_MAX_CHUNK_TOKENS
    skip_test_files: bool = True
    skip_docs: bool = True
    priority_files: list[str] = Field(default_factory=lambda: PRIORITY_FILES.copy())

    model_config = {"env_prefix": "DEPVET_DIFF_", "extra": "ignore"}


class AlertConfig(BaseSettings):
    min_severity: str = DEFAULT_MIN_SEVERITY
    slack_webhook_env: str = "DEPVET_SLACK_WEBHOOK"
    webhook_url: str = ""
    webhook_secret_env: str = "DEPVET_WEBHOOK_SECRET"

    model_config = {"env_prefix": "DEPVET_ALERT_", "extra": "ignore"}


class StateConfig(BaseSettings):
    path: str = DEFAULT_STATE_PATH

    model_config = {"env_prefix": "DEPVET_STATE_", "extra": "ignore"}


class SecurifyConfig(BaseSettings):
    enabled: bool = False
    endpoint: str = ""
    api_key_env: str = "SECURIFY_API_KEY"

    model_config = {"env_prefix": "DEPVET_SECURIFY_", "extra": "ignore"}


class DepVetConfig:
    """Top-level DepVet configuration."""

    def __init__(
        self,
        llm: Optional[LLMConfig] = None,
        monitor: Optional[MonitorConfig] = None,
        watchlist: Optional[WatchlistConfig] = None,
        diff: Optional[DiffConfig] = None,
        alert: Optional[AlertConfig] = None,
        state: Optional[StateConfig] = None,
        securify: Optional[SecurifyConfig] = None,
    ):
        self.llm = llm or LLMConfig()
        self.monitor = monitor or MonitorConfig()
        self.watchlist = watchlist or WatchlistConfig()
        self.diff = diff or DiffConfig()
        self.alert = alert or AlertConfig()
        self.state = state or StateConfig()
        self.securify = securify or SecurifyConfig()

    @property
    def llm_api_key(self) -> Optional[str]:
        return os.environ.get(self.llm.api_key_env)

    @property
    def slack_webhook_url(self) -> Optional[str]:
        return os.environ.get(self.alert.slack_webhook_env)


def load_config(config_path: Optional[str] = None) -> DepVetConfig:
    """Load configuration from a TOML file."""
    paths_to_try = []
    if config_path:
        paths_to_try.append(Path(config_path))
    paths_to_try.extend([
        Path("depvet.toml"),
        Path.home() / ".config" / "depvet" / "depvet.toml",
        Path("/etc/depvet/depvet.toml"),
    ])

    raw: dict = {}
    for path in paths_to_try:
        if path.exists() and tomllib is not None:
            with open(path, "rb") as f:
                raw = tomllib.load(f)
            break

    def _section(key: str) -> dict:
        return raw.get(key, {})

    return DepVetConfig(
        llm=LLMConfig(**_section("llm")),
        monitor=MonitorConfig(**_section("monitor")),
        watchlist=WatchlistConfig(**_section("watchlist")),
        diff=DiffConfig(**_section("diff")),
        alert=AlertConfig(**_section("alert")),
        state=StateConfig(**_section("state")),
        securify=SecurifyConfig(**_section("securify")),
    )
