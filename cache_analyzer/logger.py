"""
Structured logging for Cache-Control Analyzer.

Design goals:
  * Never log secrets (Authorization headers, cookie values, tokens,
    full sensitive response bodies).
  * Human-readable console output via `rich` when available, falling
    back to the standard library otherwise.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
}

_SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[a-z0-9\-_\.=]+"),
    re.compile(r"(?i)(password\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(token\s*[:=]\s*)\S+"),
]

_LOGGER_NAME = "cache_analyzer"


def redact(text: str) -> str:
    """Redact common secret patterns from a string before logging."""
    if not text:
        return text
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]", redacted)
    return redacted


def redact_header(name: str, value: str) -> str:
    """Redact a header value if the header name is considered sensitive."""
    if name.lower() in _SENSITIVE_HEADER_NAMES:
        return "[REDACTED]"
    return redact(value)


def get_logger(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    if logger.handlers:
        logger.setLevel(level.upper())
        return logger

    logger.setLevel(level.upper())
    handler: logging.Handler
    try:
        from rich.logging import RichHandler

        handler = RichHandler(show_time=True, show_path=False, markup=False)
        formatter = logging.Formatter("%(message)s")
    except ImportError:  # pragma: no cover - fallback path
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    return logger
