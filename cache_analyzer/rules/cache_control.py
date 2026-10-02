"""
Rule module: Cache-Control directive-level correctness and quality checks.

These rules focus on the directives themselves (conflicts, malformed
values, unusual combinations) rather than on sensitive-content
correlation, which lives in `sensitive_content.py`.
"""
from __future__ import annotations

from typing import List

from cache_analyzer.context import AnalysisContext
from cache_analyzer.models import Confidence, Finding, Severity
from cache_analyzer.rules import severity as sev


def run(context: AnalysisContext) -> List[Finding]:
    findings: List[Finding] = []
    policy = context.cache_policy

    if policy.raw_cache_control is None:
        return findings  # handled contextually by sensitive_content.py

    evidence = [f"Cache-Control: {policy.raw_cache_control}"]

    # --- Conflicting directives ------------------------------------------
    if policy.is_public and policy.is_private:
        findings.append(
            Finding(
                rule_id="CCA-010",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title="Conflicting 'public' and 'private' directives",
                description=(
                    "Both 'public' and 'private' directives are present in the same "
                    "Cache-Control header. Caches may resolve this ambiguity "
                    "inconsistently -- some implementations prioritize 'private'."
                ),
                evidence=evidence,
                affected_headers=["Cache-Control"],
                why_it_matters=(
                    "Ambiguous directives can lead to inconsistent caching behavior "
                    "across different clients, proxies, and CDNs."
                ),
                recommendation="Specify only one of 'public' or 'private' to avoid ambiguity.",
                category="cache_control",
            )
        )

    if policy.is_no_store and (policy.max_age_seconds() is not None or policy.s_maxage_seconds() is not None):
        findings.append(
            Finding(
                rule_id="CCA-011",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                title="'no-store' combined with max-age/s-maxage",
                description=(
                    "'no-store' instructs caches not to store the response at all, "
                    "making any accompanying max-age/s-maxage value redundant. This "
                    "usually indicates leftover or copy-pasted configuration rather "
                    "than a functional problem."
                ),
                evidence=evidence,
                affected_headers=["Cache-Control"],
                why_it_matters="Redundant/conflicting directives can indicate misconfiguration.",
                recommendation="Remove max-age/s-maxage when no-store is intended, for clarity.",
                category="cache_control",
            )
        )

    # --- Malformed numeric directives -------------------------------------
    for directive in ("max-age", "s-maxage", "stale-while-revalidate", "stale-if-error"):
        if policy.has_directive(directive):
            value = policy.directive_value(directive)
            if value is not None:
                try:
                    parsed = int(value)
                    if parsed < 0:
                        findings.append(_malformed_numeric_finding(directive, value, evidence, "negative value"))
                except ValueError:
                    findings.append(_malformed_numeric_finding(directive, value, evidence, "non-numeric value"))

    # --- Vary: * (effectively uncacheable, but worth flagging) -----------
    if policy.vary and policy.vary.strip() == "*":
        findings.append(
            Finding(
                rule_id="CCA-012",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                title="'Vary: *' disables effective caching",
                description=(
                    "A 'Vary: *' header indicates the response varies on criteria "
                    "that cannot be captured in a cache key, effectively making the "
                    "response uncacheable by conformant shared caches."
                ),
                evidence=[f"Vary: {policy.vary}"],
                affected_headers=["Vary"],
                why_it_matters="Confirms shared caches should not store/reuse this response.",
                recommendation="No action required if this is intentional.",
                category="cache_control",
            )
        )

    # --- immutable with very short max-age (unusual) ---------------------
    max_age = policy.max_age_seconds()
    if policy.is_immutable and max_age is not None and max_age < 86400:
        findings.append(
            Finding(
                rule_id="CCA-013",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="'immutable' used with a short max-age",
                description=(
                    f"'immutable' instructs browsers to skip revalidation entirely "
                    f"for the lifetime of the cache entry, but max-age is only "
                    f"{max_age} seconds. This combination is unusual: 'immutable' is "
                    "typically paired with long-lived, versioned/fingerprinted assets."
                ),
                evidence=evidence,
                affected_headers=["Cache-Control"],
                why_it_matters="May indicate a copy-pasted policy that doesn't match the resource's update frequency.",
                recommendation="Confirm this resource genuinely never changes within its cache lifetime.",
                category="cache_control",
            )
        )

    return findings


def _malformed_numeric_finding(directive: str, value: str, evidence: List[str], reason: str) -> Finding:
    return Finding(
        rule_id="CCA-014",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        title=f"Malformed '{directive}' directive value",
        description=(
            f"The '{directive}' directive has a {reason} ('{value}'). Clients and "
            "caches may ignore this directive entirely or fall back to default "
            "caching heuristics, which can produce unexpected behavior."
        ),
        evidence=evidence,
        affected_headers=["Cache-Control"],
        why_it_matters="Malformed directives can silently fail, leading to unintended caching behavior.",
        recommendation=f"Ensure '{directive}' is a non-negative integer representing seconds.",
        category="cache_control",
    )
