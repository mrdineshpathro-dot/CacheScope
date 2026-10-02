"""
Rule module: sensitive-content vs. cache-policy interaction.

This is the core of the analyzer -- it never claims that sensitive data
*definitely* exists, nor that a `public` directive is automatically a
confirmed vulnerability. It expresses findings as likelihoods with an
explicit confidence level and a clear rationale.
"""
from __future__ import annotations

from typing import List

from cache_analyzer.context import AnalysisContext
from cache_analyzer.models import Confidence, Finding, SensitivityLevel, Severity
from cache_analyzer.rules import severity as sev


def run(context: AnalysisContext) -> List[Finding]:
    findings: List[Finding] = []
    policy = context.cache_policy
    sensitivity = context.sensitivity
    response = context.response

    evidence_cc = [f"Cache-Control: {policy.raw_cache_control}"] if policy.raw_cache_control else []
    sensitivity_evidence = list(sensitivity.reasons)

    if sensitivity.level == SensitivityLevel.NONE:
        findings.append(
            Finding(
                rule_id="CCA-009",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="No sensitive-content indicators detected",
                description=(
                    "The available heuristics (URL pattern, headers, and optionally a "
                    "capped body sample) did not surface indicators that this response "
                    "contains sensitive, user-specific content. This does not guarantee "
                    "the response is non-sensitive -- it only reflects the limits of "
                    "passive heuristic analysis."
                ),
                evidence=sensitivity_evidence,
                affected_headers=[],
                why_it_matters="Helps prioritize review effort toward higher-likelihood findings.",
                recommendation=sev.REMEDIATION_GENERIC_REVIEW,
                category="sensitive_content",
            )
        )
        return findings

    # --- HIGH: sensitive + publicly/shared cacheable --------------------
    if sensitivity.level in (SensitivityLevel.HIGH, SensitivityLevel.MEDIUM) and policy.is_public:
        findings.append(
            Finding(
                rule_id="CCA-001",
                severity=Severity.HIGH,
                confidence=sensitivity.confidence,
                title="Potentially sensitive response is publicly cacheable",
                description=(
                    "This response shows indicators of potentially sensitive or "
                    "user-specific content, and its Cache-Control policy explicitly "
                    "permits storage by shared caches (public). Potentially sensitive "
                    "response appears cacheable by shared caches, which could result "
                    "in one user's response being served to another user if the cache "
                    "key does not sufficiently vary by identity."
                ),
                evidence=evidence_cc + sensitivity_evidence,
                affected_headers=["Cache-Control"],
                why_it_matters=(
                    "Shared caches (CDNs, reverse proxies, corporate proxies) may store "
                    "and later serve this response to a different user, potentially "
                    "exposing personal information, session context, or internal "
                    "identifiers."
                ),
                recommendation=sev.REMEDIATION_REVIEW_SHARED_CACHE + "\n\n" + sev.REMEDIATION_PRIVATE_SHORT,
                category="sensitive_content",
            )
        )
    elif sensitivity.level == SensitivityLevel.HIGH and policy.shared_cache_permitted and not policy.is_public:
        findings.append(
            Finding(
                rule_id="CCA-002",
                severity=Severity.HIGH,
                confidence=sensitivity.confidence,
                title="Potentially sensitive response appears cacheable by shared caches",
                description=(
                    "This response shows strong indicators of sensitive or "
                    "user-specific content. Although 'public' is not explicitly set, "
                    "the combination of headers present (e.g. s-maxage, CDN cache "
                    "headers, or the absence of restrictive directives) suggests a "
                    "shared cache may still be permitted to store this response."
                ),
                evidence=evidence_cc + sensitivity_evidence,
                affected_headers=["Cache-Control", "Surrogate-Control", "CDN-Cache-Control"],
                why_it_matters=(
                    "Shared-cache storage of user-specific content can lead to "
                    "cross-user data exposure even without an explicit 'public' "
                    "directive, particularly with CDN-specific override headers."
                ),
                recommendation=sev.REMEDIATION_REVIEW_SHARED_CACHE,
                category="sensitive_content",
            )
        )

    # --- MEDIUM: sensitive + missing/weak Cache-Control -----------------
    if sensitivity.level in (SensitivityLevel.HIGH, SensitivityLevel.MEDIUM):
        if policy.raw_cache_control is None:
            findings.append(
                Finding(
                    rule_id="CCA-003",
                    severity=Severity.MEDIUM,
                    confidence=sensitivity.confidence,
                    title="Potentially sensitive response is missing a Cache-Control header",
                    description=(
                        "No Cache-Control header was present on a response with "
                        "indicators of sensitive or user-specific content. Without an "
                        "explicit directive, caching behavior depends on client/proxy "
                        "heuristics (e.g. Expires, Last-Modified) and may be "
                        "inconsistent or overly permissive."
                    ),
                    evidence=sensitivity_evidence,
                    affected_headers=["Cache-Control"],
                    why_it_matters=(
                        "Relying on implicit/heuristic caching behavior for "
                        "sensitive content can lead to unintended caching by "
                        "browsers or intermediary caches."
                    ),
                    recommendation=sev.REMEDIATION_GENERIC_REVIEW + "\n\n" + sev.REMEDIATION_PRIVATE_SHORT,
                    category="sensitive_content",
                )
            )

        max_age = policy.max_age_seconds()
        if max_age is not None and max_age > 3600 and not policy.is_private:
            findings.append(
                Finding(
                    rule_id="CCA-004",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title="Long max-age on potentially sensitive, non-private response",
                    description=(
                        f"The response specifies max-age={max_age} seconds "
                        f"(~{round(max_age / 3600, 1)}h) without a 'private' directive, "
                        "on a response with indicators of sensitive content. Long "
                        "cache lifetimes increase the window during which a stale or "
                        "misdirected cached copy could be served."
                    ),
                    evidence=evidence_cc + sensitivity_evidence,
                    affected_headers=["Cache-Control"],
                    why_it_matters=(
                        "A long cache lifetime magnifies the impact of any cache-key "
                        "or scoping mistake, and increases exposure time for stale "
                        "sensitive data."
                    ),
                    recommendation=sev.REMEDIATION_REVIEW_SHARED_CACHE,
                    category="sensitive_content",
                )
            )

        s_maxage = policy.s_maxage_seconds()
        if s_maxage is not None:
            findings.append(
                Finding(
                    rule_id="CCA-005",
                    severity=Severity.MEDIUM,
                    confidence=sensitivity.confidence,
                    title="s-maxage present on potentially user-specific content",
                    description=(
                        f"The response sets s-maxage={s_maxage}, which specifically "
                        "targets shared caches, on content that shows indicators of "
                        "being user-specific. Shared caches generally ignore 'private' "
                        "when 's-maxage' is present, which can widen exposure."
                    ),
                    evidence=evidence_cc + sensitivity_evidence,
                    affected_headers=["Cache-Control"],
                    why_it_matters=(
                        "s-maxage explicitly instructs shared/proxy caches on how "
                        "long to retain a response, which is risky if the response is "
                        "not safe to share across users."
                    ),
                    recommendation=sev.REMEDIATION_REVIEW_SHARED_CACHE,
                    category="sensitive_content",
                )
            )

    # --- LOW / INFORMATIONAL: good practice recognized -------------------
    if sensitivity.level != SensitivityLevel.NONE:
        if policy.is_no_store:
            findings.append(
                Finding(
                    rule_id="CCA-006",
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="Explicit no-store directive on potentially sensitive content",
                    description=(
                        "The response explicitly disables caching via 'no-store', "
                        "which is a strong, appropriate control for sensitive content."
                    ),
                    evidence=evidence_cc,
                    affected_headers=["Cache-Control"],
                    why_it_matters="Confirms caching is explicitly disabled for this response.",
                    recommendation="No action required; this reflects a safe default.",
                    category="sensitive_content",
                )
            )
        elif policy.is_private and policy.s_maxage_seconds() is None:
            findings.append(
                Finding(
                    rule_id="CCA-007",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    title="Private caching directive limits exposure on potentially sensitive content",
                    description=(
                        "The response specifies 'private', restricting caching to the "
                        "end-user's browser and excluding shared caches. This is a "
                        "reasonable control, though verify the max-age is appropriate "
                        "for the sensitivity of the content."
                    ),
                    evidence=evidence_cc,
                    affected_headers=["Cache-Control"],
                    why_it_matters="Reduces (but does not eliminate) caching-related exposure risk.",
                    recommendation=sev.REMEDIATION_GENERIC_REVIEW,
                    category="sensitive_content",
                )
            )
        elif policy.max_age_seconds() is not None and policy.max_age_seconds() <= 300:
            findings.append(
                Finding(
                    rule_id="CCA-008",
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    title="Short-lived cache configuration observed",
                    description=(
                        f"max-age={policy.max_age_seconds()} seconds is a relatively "
                        "short cache lifetime, limiting the window of potential "
                        "exposure if the response were cached inappropriately."
                    ),
                    evidence=evidence_cc,
                    affected_headers=["Cache-Control"],
                    why_it_matters="Short cache lifetimes reduce -- but do not eliminate -- risk.",
                    recommendation=sev.REMEDIATION_GENERIC_REVIEW,
                    category="sensitive_content",
                )
            )

    return findings
