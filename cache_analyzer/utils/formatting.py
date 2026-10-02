"""
Shared formatting helpers for reports (terminal, HTML, Markdown, CSV).
"""
from __future__ import annotations

import html
from typing import Optional


def human_bytes(num_bytes: Optional[int]) -> str:
    if num_bytes is None:
        return "unknown"
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def human_seconds(seconds: Optional[float]) -> str:
    if seconds is None:
        return "unknown"
    return f"{seconds:.2f}s"


def escape_html(text: str) -> str:
    return html.escape(text, quote=True)


def truncate(text: str, max_len: int = 200) -> str:
    if text is None:
        return ""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "\u2026"


SEVERITY_COLORS = {
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFORMATIONAL": "grey62",
}

SEVERITY_HTML_COLORS = {
    "HIGH": "#c0392b",
    "MEDIUM": "#d68910",
    "LOW": "#2980b9",
    "INFORMATIONAL": "#7f8c8d",
}
