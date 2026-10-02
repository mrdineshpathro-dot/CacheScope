"""
Low-level HTTP parsing helpers shared by the fetcher and parser modules.

These functions are pure (no network I/O) so that they can be unit
tested in isolation and reused across the "URL", "raw response",
"headers file", and "JSON" input modes.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from cache_analyzer.models import CookieInfo

_STATUS_LINE_RE = re.compile(
    r"^HTTP/(?P<version>\d(?:\.\d)?)\s+(?P<status>\d{3})(?:\s+(?P<reason>.*))?$"
)


def parse_status_line(line: str) -> Tuple[Optional[str], int, Optional[str]]:
    """Parse an HTTP status line like 'HTTP/1.1 200 OK'.

    Returns (http_version, status_code, reason). Falls back gracefully
    on malformed input.
    """
    line = line.strip()
    match = _STATUS_LINE_RE.match(line)
    if not match:
        return None, 0, None
    version = match.group("version")
    status = int(match.group("status"))
    reason = match.group("reason")
    return version, status, reason


def parse_raw_headers(lines: List[str]) -> Dict[str, str]:
    """Parse a list of 'Name: Value' header lines into a dict.

    Duplicate headers are merged with a comma, per RFC 7230 semantics
    (except Set-Cookie, which is handled separately by callers because
    commas are valid inside cookie expiry dates).
    """
    headers: Dict[str, str] = {}
    multi_value_as_list: Dict[str, List[str]] = {}

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue
        if ":" not in line:
            # Malformed header line -- skip rather than raise, since
            # real-world servers occasionally emit odd formatting.
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        value = value.strip()
        if not name:
            continue

        key_lower = name.lower()
        if key_lower == "set-cookie":
            multi_value_as_list.setdefault(name, []).append(value)
            continue

        if name in headers:
            headers[name] = f"{headers[name]}, {value}"
        else:
            headers[name] = value

    # Re-attach Set-Cookie headers using a sentinel join that downstream
    # cookie parsing can split back apart safely (cookies cannot contain
    # the NUL character).
    for name, values in multi_value_as_list.items():
        headers[name] = "\x00".join(values)

    return headers


def split_header_body(raw_text: str) -> Tuple[List[str], Optional[str]]:
    """Split a raw HTTP response into (header_lines, body) on blank line."""
    normalized = raw_text.replace("\r\n", "\n")
    if "\n\n" in normalized:
        header_part, _, body = normalized.partition("\n\n")
    else:
        header_part, body = normalized, None
    header_lines = header_part.split("\n")
    return header_lines, body


def get_set_cookie_values(headers: Dict[str, str]) -> List[str]:
    """Extract individual Set-Cookie header values (handles merged ones)."""
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            if "\x00" in value:
                return value.split("\x00")
            return [value]
    return []


_COOKIE_ATTR_BOOL = {"secure", "httponly"}


def parse_set_cookie(value: str) -> CookieInfo:
    """Parse a single Set-Cookie header value into a CookieInfo model."""
    parts = [p.strip() for p in value.split(";") if p.strip()]
    if not parts:
        return CookieInfo(name="", raw=value)

    name_value = parts[0]
    name, _, cookie_value = name_value.partition("=")
    name = name.strip()

    info = CookieInfo(name=name or "unknown", raw=value)

    for attr in parts[1:]:
        if "=" in attr:
            attr_name, _, attr_value = attr.partition("=")
            attr_name_lower = attr_name.strip().lower()
            attr_value = attr_value.strip()
        else:
            attr_name_lower = attr.strip().lower()
            attr_value = None

        if attr_name_lower == "secure":
            info.secure = True
        elif attr_name_lower == "httponly":
            info.http_only = True
        elif attr_name_lower == "samesite":
            info.same_site = attr_value
        elif attr_name_lower == "max-age":
            try:
                info.max_age = int(attr_value) if attr_value is not None else None
            except ValueError:
                info.max_age = None
        elif attr_name_lower == "expires":
            info.expires = attr_value
        elif attr_name_lower == "domain":
            info.domain = attr_value
        elif attr_name_lower == "path":
            info.path = attr_value

    return info


def parse_all_cookies(headers: Dict[str, str]) -> List[CookieInfo]:
    return [parse_set_cookie(v) for v in get_set_cookie_values(headers)]


def guess_content_type(headers: Dict[str, str]) -> Optional[str]:
    for key, value in headers.items():
        if key.lower() == "content-type":
            return value.split(";")[0].strip()
    return None


def guess_content_length(headers: Dict[str, str], body: Optional[str]) -> Optional[int]:
    for key, value in headers.items():
        if key.lower() == "content-length":
            try:
                return int(value.strip())
            except ValueError:
                break
    if body is not None:
        return len(body.encode("utf-8", errors="ignore"))
    return None
