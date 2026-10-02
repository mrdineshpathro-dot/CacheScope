"""
Rule module: cookie-aware cache analysis.

This module inspects `Set-Cookie` attributes, but only reports findings
that specifically relate cookies to CACHING behavior -- general cookie
security posture (e.g. missing Secure/HttpOnly outside of a caching
context) is out of scope for this tool.
"""
from __future__ import annotations

from typing import List

from cache_analyzer.context import AnalysisContext
from cache_analyzer.models import Confidence, Finding, Severity

_COOKIE_CACHE_SAFE_VARY_TOKENS = ("cookie",)


def run(context: AnalysisContext) -> List[Finding]:
    findings: List[Finding] = []
    response = context.response
    policy = context.cache_policy

    session_cookies = [c for c in response.cookies if c.looks_session_related()]
    if not session_cookies:
        return findings

    cookie_names = ", ".join(c.name for c in session_cookies)
    vary_lower = (policy.vary or "").lower()
    varies_by_cookie = any(token in vary_lower for token in _COOKIE_CACHE_SAFE_VARY_TOKENS)

    if policy.shared_cache_permitted and not varies_by_cookie:
        findings.append(
            Finding(
                rule_id="CCA-030",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title="Session-related cookie present on a shared-cacheable response without cache-key discrimination",
                description=(
                    f"Session/auth-like cookie(s) ({cookie_names}) were set on a "
                    "response whose Cache-Control policy appears to permit shared "
                    "cache storage, without a 'Vary: Cookie' (or equivalent) header "
                    "to discriminate the cache key by identity. Shared caches "
                    "typically ignore cookies when building a cache key unless "
                    "instructed otherwise, which can risk serving one user's "
                    "response (and their cookie-driven personalization) to another."
                ),
                evidence=[f"Set-Cookie present for: {cookie_names}"]
                + ([f"Cache-Control: {policy.raw_cache_control}"] if policy.raw_cache_control else ["Cache-Control: (missing)"])
                + ([f"Vary: {policy.vary}"] if policy.vary else ["Vary: (missing)"]),
                affected_headers=["Set-Cookie", "Cache-Control", "Vary"],
                why_it_matters=(
                    "If a shared cache stores this response and later replays it to "
                    "a different client, that client could receive another user's "
                    "session-influenced content."
                ),
                recommendation=(
                    "If this response is genuinely user-specific, prefer "
                    "'Cache-Control: private' (or 'no-store') over shared caching. "
                    "If shared caching is required, ensure the cache key accounts "
                    "for identity-relevant request attributes."
                ),
                category="cookies",
            )
        )

    unprotected = [c for c in session_cookies if not c.secure or not c.http_only]
    if unprotected:
        names = ", ".join(c.name for c in unprotected)
        findings.append(
            Finding(
                rule_id="CCA-031",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                title="Session-related cookie(s) missing Secure/HttpOnly while response may be cached",
                description=(
                    f"Cookie(s) {names} appear session-related and are missing the "
                    "Secure and/or HttpOnly attribute. While primarily a general "
                    "cookie-security concern, this is noted here because it "
                    "compounds the impact of any cache-related exposure of this "
                    "response."
                ),
                evidence=[c.raw for c in unprotected],
                affected_headers=["Set-Cookie"],
                why_it_matters="Increases the impact of cache-related or transport-related cookie exposure.",
                recommendation="Set 'Secure' and 'HttpOnly' on session/authentication cookies.",
                category="cookies",
            )
        )

    return findings
