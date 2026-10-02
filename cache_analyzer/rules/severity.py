"""
Shared severity/confidence helpers and standard remediation language.

This module intentionally contains no "rules" of its own -- it is a
toolbox used by the other rule modules so that wording and severity
reasoning stay consistent across the engine.
"""
from __future__ import annotations

from cache_analyzer.models import Confidence, Severity

# Standard remediation snippets. The tool explicitly avoids recommending
# `no-store` universally -- the right policy depends on the endpoint.
REMEDIATION_NO_STORE = (
    "For responses that may contain highly sensitive, user-specific data "
    "(authentication, payment, personal data), consider:\n"
    "    Cache-Control: no-store\n"
    "This prevents browsers and shared caches from persisting the response."
)

REMEDIATION_PRIVATE_SHORT = (
    "If the response is only ever useful to the current user and browser-side "
    "caching is acceptable, consider:\n"
    "    Cache-Control: private, max-age=300\n"
    "This allows the browser to cache the response privately while preventing "
    "shared caches (proxies, CDNs) from storing it."
)

REMEDIATION_REVIEW_SHARED_CACHE = (
    "Review whether this endpoint is intended to be cached by shared/shared-aware "
    "infrastructure (CDNs, reverse proxies). If the content is user-specific, "
    "restrict caching to the browser only (private) or disable caching entirely "
    "(no-store), depending on sensitivity. If shared caching is intentional and "
    "the content is not user-specific, no change may be required."
)

REMEDIATION_ADD_VARY_COOKIE = (
    "If a shared cache must be used for a response that varies by session, ensure "
    "the response declares 'Vary: Cookie' (or an equivalent discriminator) so "
    "caches do not serve one user's cached response to another user. Note this "
    "alone does not guarantee privacy for all caches and is not a substitute for "
    "appropriate Cache-Control directives."
)

REMEDIATION_AUTHORIZATION_CACHING = (
    "Per RFC 7234, shared caches must not store a response to a request containing "
    "an Authorization header unless the response explicitly allows it via "
    "'public', 'must-revalidate', or 's-maxage'. If this endpoint is authenticated, "
    "verify that shared caching is genuinely intended before using these directives."
)

REMEDIATION_GENERIC_REVIEW = (
    "The appropriate caching policy depends on the specific application's "
    "requirements. Review this endpoint's intended audience (single user vs. "
    "general public) and choose Cache-Control directives accordingly."
)


def confidence_for(path_hits: int, has_strong_signal: bool) -> Confidence:
    """Shared helper to compute a confidence level from heuristic signal counts."""
    if has_strong_signal and path_hits >= 1:
        return Confidence.HIGH
    if has_strong_signal or path_hits >= 2:
        return Confidence.MEDIUM
    return Confidence.LOW
