"""
Input validation helpers.

These helpers are intentionally conservative: anything that cannot be
clearly validated is rejected rather than silently "fixed", since this
tool is meant to be used safely against systems the user is authorized
to test.
"""
from __future__ import annotations

import os
import re
from urllib.parse import urlparse

_ALLOWED_SCHEMES = {"http", "https"}

# Private / loopback / link-local ranges that we warn about by default.
# We do not hard-block these because authorized lab testing (e.g. against
# localhost or an internal staging host) is a legitimate use case, but we
# surface a clear warning so users are aware of what they are scanning.
_PRIVATE_HOST_PATTERNS = [
    re.compile(r"^localhost$", re.IGNORECASE),
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^\[?::1\]?$"),
]


class ValidationError(ValueError):
    """Raised when user-supplied input fails validation."""


def validate_url(url: str) -> str:
    """Validate a URL is well-formed and uses an allowed scheme.

    Returns the normalized URL string, or raises ValidationError.
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string.")

    url = url.strip()
    parsed = urlparse(url)

    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ValidationError(
            f"Unsupported URL scheme '{parsed.scheme}'. Only http/https are allowed."
        )
    if not parsed.netloc:
        raise ValidationError(f"URL is missing a host: {url!r}")

    return url


def is_private_host(url: str) -> bool:
    """Best-effort check for private/loopback hosts (for warnings only)."""
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return False
    return any(pattern.search(host) for pattern in _PRIVATE_HOST_PATTERNS)


def sanitize_filename(name: str) -> str:
    """Sanitize a filename to prevent path traversal / unsafe characters."""
    if not name:
        return "output"
    # Strip any directory components to prevent path traversal.
    name = os.path.basename(name)
    name = name.replace("\x00", "")
    name = re.sub(r"[^A-Za-z0-9._\-]", "_", name)
    name = name.lstrip(".")  # avoid hidden files / relative traversal tricks
    return name or "output"


def safe_output_path(path: str, base_dir: str = "output") -> str:
    """Resolve an output path, preventing path traversal outside base_dir.

    If `path` looks like a plain filename, it is placed inside `base_dir`.
    If it is an absolute or relative path with directories, those
    directories are preserved but normalized, and traversal attempts
    ('..') are stripped.
    """
    base_dir_abs = os.path.abspath(base_dir)
    directory, filename = os.path.split(path)
    filename = sanitize_filename(filename)

    if not directory:
        final_dir = base_dir_abs
    else:
        # Normalize and strip leading '..' / absolute escape attempts.
        normalized = os.path.normpath(directory)
        parts = [p for p in normalized.split(os.sep) if p not in ("..", "")]
        final_dir = os.path.abspath(os.path.join(base_dir_abs, *parts)) if parts else base_dir_abs

    os.makedirs(final_dir, exist_ok=True)
    return os.path.join(final_dir, filename)


def validate_file_path(path: str) -> str:
    """Validate that a local input file path exists and is a regular file."""
    if not path or not isinstance(path, str):
        raise ValidationError("File path must be a non-empty string.")
    if not os.path.isfile(path):
        raise ValidationError(f"File not found: {path}")
    return path
