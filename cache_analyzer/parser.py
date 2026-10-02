"""
Parsing layer: turns raw input (Cache-Control header strings, raw HTTP
responses, header files, JSON files) into normalized, typed models
(`CachePolicy`, `HttpResponse`).

This module performs no network I/O.
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

from cache_analyzer.models import CachePolicy, HttpResponse, RedirectHop
from cache_analyzer.utils.http import (
    guess_content_length,
    guess_content_type,
    parse_all_cookies,
    parse_raw_headers,
    parse_status_line,
    split_header_body,
)
from cache_analyzer.utils.validators import ValidationError, validate_file_path

# Directives that take a numeric/quoted parameter rather than being a bare flag.
_PARAMETERIZED_DIRECTIVES = {
    "max-age",
    "s-maxage",
    "stale-while-revalidate",
    "stale-if-error",
}


def parse_cache_control(value: Optional[str]) -> Dict[str, Optional[str]]:
    """Parse a Cache-Control header value into a dict of directives.

    Handles:
      * multiple comma-separated directives
      * directive parameters (max-age=600)
      * quoted parameter values ("no-cache"="Set-Cookie")
      * duplicate directives (last one wins, but parsing never raises)
      * irregular whitespace / casing
      * malformed / trailing commas
    """
    directives: Dict[str, Optional[str]] = {}
    if not value:
        return directives

    # Split on commas that are not inside double quotes.
    tokens = _split_respecting_quotes(value, ",")

    for raw_token in tokens:
        token = raw_token.strip()
        if not token:
            continue
        if "=" in token:
            name, _, param = token.partition("=")
            name = name.strip().lower()
            param = param.strip()
            if len(param) >= 2 and param[0] == '"' and param[-1] == '"':
                param = param[1:-1]
            if not name:
                continue
            directives[name] = param
        else:
            name = token.lower()
            if not name:
                continue
            directives[name] = None

    return directives


def _split_respecting_quotes(value: str, delimiter: str) -> List[str]:
    tokens: List[str] = []
    current = []
    in_quotes = False
    for ch in value:
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
        elif ch == delimiter and not in_quotes:
            tokens.append("".join(current))
            current = []
        else:
            current.append(ch)
    tokens.append("".join(current))
    return tokens


def _safe_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return None


def build_cache_policy(headers: Dict[str, str]) -> CachePolicy:
    """Build a CachePolicy from a case-insensitive headers mapping."""

    def get(name: str) -> Optional[str]:
        name_lower = name.lower()
        for key, val in headers.items():
            if key.lower() == name_lower:
                return val
        return None

    raw_cc = get("Cache-Control")
    directives = parse_cache_control(raw_cc)

    return CachePolicy(
        raw_cache_control=raw_cc,
        directives=directives,
        pragma=get("Pragma"),
        expires=get("Expires"),
        age=_safe_int(get("Age")),
        etag=get("ETag"),
        vary=get("Vary"),
        last_modified=get("Last-Modified"),
        surrogate_control=get("Surrogate-Control"),
        cdn_cache_control=get("CDN-Cache-Control"),
        cloudflare_cdn_cache_control=get("Cloudflare-CDN-Cache-Control"),
    )


def response_from_headers_dict(
    url: str,
    headers: Dict[str, str],
    status_code: int = 200,
    body: Optional[str] = None,
    source: str = "headers_file",
) -> HttpResponse:
    cookies = parse_all_cookies(headers)
    return HttpResponse(
        url=url,
        final_url=url,
        status_code=status_code,
        headers=headers,
        body=body,
        content_type=guess_content_type(headers),
        content_length=guess_content_length(headers, body),
        server=headers.get("Server") or headers.get("server"),
        cookies=cookies,
        source=source,
    )


def parse_headers_file(path: str, url: str = "local://headers-file") -> HttpResponse:
    """Parse a plain text file containing one 'Name: Value' header per line.

    An optional leading HTTP status line is also supported.
    """
    validate_file_path(path)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    lines = [l for l in content.replace("\r\n", "\n").split("\n")]
    status_code = 200
    http_version = None
    reason = None

    if lines and lines[0].strip().upper().startswith("HTTP/"):
        http_version, parsed_status, reason = parse_status_line(lines[0])
        if parsed_status:
            status_code = parsed_status
        lines = lines[1:]

    headers = parse_raw_headers(lines)
    response = response_from_headers_dict(url, headers, status_code=status_code, source="headers_file")
    response.http_version = http_version
    response.reason = reason
    response.raw_header_lines = lines
    return response


def parse_raw_response_file(path: str, url: str = "local://raw-response") -> HttpResponse:
    """Parse a raw HTTP response (status line + headers + optional body)."""
    validate_file_path(path)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    header_lines, body = split_header_body(content)

    status_code = 200
    http_version = None
    reason = None

    if header_lines and header_lines[0].strip().upper().startswith("HTTP/"):
        http_version, parsed_status, reason = parse_status_line(header_lines[0])
        if parsed_status:
            status_code = parsed_status
        header_lines = header_lines[1:]

    headers = parse_raw_headers(header_lines)
    response = response_from_headers_dict(url, headers, status_code=status_code, body=body, source="raw_response")
    response.http_version = http_version
    response.reason = reason
    response.raw_header_lines = header_lines
    return response


def parse_json_response_file(path: str) -> HttpResponse:
    """Parse a JSON description of an HTTP response.

    Expected (flexible) schema::

        {
          "url": "https://example.com/account",
          "status_code": 200,
          "headers": {"Cache-Control": "public, max-age=600", ...},
          "body": "...optional...",
          "redirect_chain": [{"url": "...", "status_code": 301}, ...]
        }
    """
    validate_file_path(path)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValidationError("JSON response file must contain a top-level object.")

    url = data.get("url") or "local://json-input"
    headers = data.get("headers") or {}
    if not isinstance(headers, dict):
        raise ValidationError("'headers' field must be an object of name/value pairs.")
    headers = {str(k): str(v) for k, v in headers.items()}

    status_code = int(data.get("status_code", 200) or 200)
    body = data.get("body")
    redirect_chain_raw = data.get("redirect_chain") or []
    redirect_chain = [
        RedirectHop(url=str(hop.get("url", "")), status_code=int(hop.get("status_code", 0)))
        for hop in redirect_chain_raw
        if isinstance(hop, dict)
    ]

    response = response_from_headers_dict(url, headers, status_code=status_code, body=body, source="json")
    response.final_url = data.get("final_url", url)
    response.http_version = data.get("http_version")
    response.reason = data.get("reason")
    response.redirect_chain = redirect_chain
    response.response_time_seconds = data.get("response_time_seconds")
    response.tls_version = data.get("tls_version")
    response.tls_cipher = data.get("tls_cipher")
    return response
