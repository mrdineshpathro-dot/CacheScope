"""
Runtime configuration for Cache-Control Analyzer.

Centralizes defaults that can be overridden via CLI flags or a `.env`
file. Nothing here performs network calls or side effects at import
time.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    val = os.getenv(name)
    if val is None:
        return default
    try:
        return float(val)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


DEFAULT_USER_AGENT = "CacheControlAnalyzer/1.0 (+https://buymeacoffee.com/mrdineshpathro)"

# Hard safety ceilings -- CLI flags cannot exceed these.
MAX_ALLOWED_REDIRECTS = 20
MAX_ALLOWED_TIMEOUT = 120.0
MAX_ALLOWED_BODY_BYTES = 10 * 1024 * 1024  # 10 MB hard ceiling
MAX_ALLOWED_WORKERS = 32


@dataclass
class AppConfig:
    """Mutable application configuration used throughout a single run."""

    timeout_seconds: float = field(default_factory=lambda: _env_float("CCA_TIMEOUT", 10.0))
    user_agent: str = field(default_factory=lambda: os.getenv("CCA_USER_AGENT", DEFAULT_USER_AGENT))
    follow_redirects: bool = field(default_factory=lambda: _env_bool("CCA_FOLLOW_REDIRECTS", True))
    max_redirects: int = field(default_factory=lambda: _env_int("CCA_MAX_REDIRECTS", 5))
    insecure: bool = field(default_factory=lambda: _env_bool("CCA_INSECURE", False))
    verbose: bool = False
    no_body: bool = field(default_factory=lambda: _env_bool("CCA_NO_BODY", False))
    max_body_bytes: int = field(default_factory=lambda: _env_int("CCA_MAX_BODY_BYTES", 262_144))
    workers: int = field(default_factory=lambda: _env_int("CCA_WORKERS", 5))
    rate_limit_per_sec: float = field(default_factory=lambda: _env_float("CCA_RATE_LIMIT", 5.0))
    retries: int = field(default_factory=lambda: _env_int("CCA_RETRIES", 2))
    output_dir: str = field(default_factory=lambda: os.getenv("CCA_OUTPUT_DIR", "output"))
    log_level: str = field(default_factory=lambda: os.getenv("CCA_LOG_LEVEL", "INFO"))

    def clamp(self) -> "AppConfig":
        """Clamp user-supplied values to safe ceilings."""
        self.timeout_seconds = min(max(self.timeout_seconds, 0.5), MAX_ALLOWED_TIMEOUT)
        self.max_redirects = min(max(self.max_redirects, 0), MAX_ALLOWED_REDIRECTS)
        self.max_body_bytes = min(max(self.max_body_bytes, 0), MAX_ALLOWED_BODY_BYTES)
        self.workers = min(max(self.workers, 1), MAX_ALLOWED_WORKERS)
        self.rate_limit_per_sec = min(max(self.rate_limit_per_sec, 0.1), 50.0)
        self.retries = min(max(self.retries, 0), 5)
        return self


def default_config() -> AppConfig:
    return AppConfig().clamp()
