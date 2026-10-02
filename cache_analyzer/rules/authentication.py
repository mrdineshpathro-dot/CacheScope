"""
Rule module: authentication-aware caching heuristics.

Per RFC 7234 section 3.2, shared caches must not store a response to a
request containing an Authorization header unless the response
explicitly allows it via 'public', 'must-revalidate', or 's-maxage'.
This module checks for that specific, well-defined condition, and
otherwise treats authentication/URL indicators as heuristics only.
"""
from __future__ import annotations

from typing import List

from cache_analyzer.context import AnalysisContext
from cache_analyzer.models import Confidence, Finding, Severity
from cache_analyzer.rules import severity as sev

_AUTH_ALLOWED_OVERRIDES = {"public", "must-revalidate", "s-maxage"}


def run(context: AnalysisContext) -> List[Finding]:
    findings: List[Finding] = []
    response = context.response
    policy = context.cache_policy

    if not response.has_authorization_header():
        return findings

    directives_present = set(policy.directives.keys())
    has_override = bool(directives_present & _AUTH_ALLOWED_OVERRIDES)

    if has_override:
        overrides = sorted(directives_present & _AUTH_ALLOWED_OVERRIDES)
        findings.append(
            Finding(
                rule_id="CCA-040",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Authenticated request response explicitly permits shared caching",
                description=(
                    "The request included an Authorization header, and the response's "
                    "Cache-Control explicitly includes one of 'public', "
                    "'must-revalidate', or 's-maxage' (" + ", ".join(overrides) + "), "
                    "which per RFC 7234 permits shared caches to store an otherwise "
                    "authorization-gated response."
                ),
                evidence=[f"Cache-Control: {policy.raw_cache_control}", "Authorization header present on request"],
                affected_headers=["Cache-Control", "Authorization"],
                why_it_matters=(
                    "Explicitly allowing shared-cache storage of authenticated "
                    "responses can expose one authenticated user's data to another "
                    "client if the cache key does not fully capture identity."
                ),
                recommendation=sev.REMEDIATION_AUTHORIZATION_CACHING,
                category="authentication",
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="CCA-041",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                title="Authenticated request without explicit shared-cache override",
                description=(
                    "The request included an Authorization header. No 'public', "
                    "'must-revalidate', or 's-maxage' directive was found, so per "
                    "RFC 7234 shared caches should not store this response by "
                    "default. This is the expected/safe behavior."
                ),
                evidence=[f"Cache-Control: {policy.raw_cache_control or '(missing)'}"],
                affected_headers=["Cache-Control", "Authorization"],
                why_it_matters="Confirms the response follows the default, safer caching behavior for authenticated requests.",
                recommendation="No action required; monitor for future configuration changes.",
                category="authentication",
            )
        )

    return findings
