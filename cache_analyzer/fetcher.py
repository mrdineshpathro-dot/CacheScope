"""
Safe HTTP fetching for Cache-Control Analyzer.

This module performs read-only `GET`/`HEAD` requests against
explicitly supplied, user-authorized URLs. It never submits forms,
never retries destructive methods, and never attempts cache
manipulation or exploitation of any kind.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Optional

import httpx

from cache_analyzer.config import AppConfig
from cache_analyzer.logger import get_logger
from cache_analyzer.models import HttpResponse, RedirectHop
from cache_analyzer.utils.http import guess_content_length, guess_content_type, parse_all_cookies
from cache_analyzer.utils.validators import ValidationError, validate_url

logger = get_logger()


class FetchError(RuntimeError):
    """Raised when a URL cannot be fetched safely."""


@dataclass
class FetchOptions:
    timeout_seconds: float = 10.0
    user_agent: str = "CacheControlAnalyzer/1.0"
    follow_redirects: bool = True
    max_redirects: int = 5
    insecure: bool = False
    method: str = "GET"
    no_body: bool = True
    max_body_bytes: int = 262_144
    retries: int = 2


def _method_is_safe(method: str) -> str:
    method = method.upper().strip()
    if method not in {"GET", "HEAD"}:
        raise ValidationError(
            f"Unsupported HTTP method '{method}'. Only GET and HEAD are permitted "
            "(this tool performs passive, read-only analysis)."
        )
    return method


def fetch_url(url: str, options: Optional[FetchOptions] = None) -> HttpResponse:
    """Fetch a single URL and return a normalized HttpResponse.

    Safety properties:
      * Only GET/HEAD are allowed.
      * TLS certificates are verified by default (``--insecure`` opts out,
        intended for lab/testing environments only).
      * Redirects are capped by ``max_redirects`` and the full chain is
        recorded.
      * Response bodies are capped at ``max_body_bytes`` to avoid
        unbounded memory consumption; bodies are skipped entirely when
        ``no_body`` is set (the default), since only metadata is needed
        for most caching analysis.
    """
    options = options or FetchOptions()
    url = validate_url(url)
    method = _method_is_safe(options.method)

    headers = {"User-Agent": options.user_agent}
    redirect_chain: List[RedirectHop] = []

    last_exc: Optional[Exception] = None
    attempts = max(1, options.retries + 1)

    for attempt in range(attempts):
        try:
            start = time.monotonic()
            with httpx.Client(
                verify=not options.insecure,
                follow_redirects=False,
                timeout=options.timeout_seconds,
            ) as client:
                current_url = url
                response = None
                for _ in range(options.max_redirects + 1):
                    response = client.request(method, current_url, headers=headers)
                    if response.is_redirect and options.follow_redirects:
                        redirect_chain.append(
                            RedirectHop(url=str(response.url), status_code=response.status_code)
                        )
                        next_url = response.headers.get("location")
                        if not next_url:
                            break
                        current_url = str(httpx.URL(current_url).join(next_url))
                        continue
                    break
                elapsed = time.monotonic() - start

            if response is None:
                raise FetchError("No response received.")

            body_text: Optional[str] = None
            truncated = False
            if not options.no_body and method == "GET":
                raw = response.content
                if len(raw) > options.max_body_bytes:
                    raw = raw[: options.max_body_bytes]
                    truncated = True
                body_text = raw.decode(response.encoding or "utf-8", errors="replace")

            headers_dict = {k: v for k, v in response.headers.items()}
            cookies = parse_all_cookies(headers_dict)

            tls_version = None
            tls_cipher = None
            try:
                network_stream = response.extensions.get("network_stream")
                if network_stream is not None:
                    ssl_obj = network_stream.get_extra_info("ssl_object")
                    if ssl_obj is not None:
                        tls_version = ssl_obj.version()
                        cipher = ssl_obj.cipher()
                        if cipher:
                            tls_cipher = cipher[0]
            except Exception:  # pragma: no cover - best-effort only
                pass

            http_version = response.http_version

            result = HttpResponse(
                url=url,
                final_url=str(response.url),
                status_code=response.status_code,
                http_version=http_version,
                reason=response.reason_phrase,
                headers=headers_dict,
                body=body_text,
                body_truncated=truncated,
                content_type=guess_content_type(headers_dict),
                content_length=guess_content_length(headers_dict, body_text),
                server=headers_dict.get("Server") or headers_dict.get("server"),
                response_time_seconds=round(elapsed, 4),
                redirect_chain=redirect_chain,
                tls_version=tls_version,
                tls_cipher=tls_cipher,
                cookies=cookies,
                source="url",
            )
            return result
        except httpx.TimeoutException as exc:
            last_exc = exc
            logger.warning("Timeout fetching %s (attempt %d/%d)", url, attempt + 1, attempts)
        except httpx.RequestError as exc:
            last_exc = exc
            logger.warning("Request error fetching %s: %s (attempt %d/%d)", url, exc, attempt + 1, attempts)
        time.sleep(min(2 ** attempt * 0.25, 2.0))

    raise FetchError(f"Failed to fetch {url}: {last_exc}") from last_exc


def fetch_from_config(url: str, config: AppConfig, method: str = "GET") -> HttpResponse:
    options = FetchOptions(
        timeout_seconds=config.timeout_seconds,
        user_agent=config.user_agent,
        follow_redirects=config.follow_redirects,
        max_redirects=config.max_redirects,
        insecure=config.insecure,
        method=method,
        no_body=config.no_body,
        max_body_bytes=config.max_body_bytes,
        retries=config.retries,
    )
    return fetch_url(url, options)
