"""
Rule module: CDN / shared-cache specific header analysis.

Covers `Surrogate-Control`, `CDN-Cache-Control`, and
`Cloudflare-CDN-Cache-Control`, which can override standard
Cache-Control behavior specifically for CDN/proxy layers.
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

    cdn_headers = {
        "Surrogate-Control": policy.surrogate_control,
        "CDN-Cache-Control": policy.cdn_cache_control,
        "Cloudflare-CDN-Cache-Control": policy.cloudflare_cdn_cache_control,
    }
    present = {name: value for name, value in cdn_headers.items() if value}
    if not present:
        return findings

    evidence = [f"{name}: {value}" for name, value in present.items()]

    permits_storage = any(
        "no-store" not in (value or "").lower() for value in present.values()
    )

    if sensitivity.level in (SensitivityLevel.HIGH, SensitivityLevel.MEDIUM) and permits_storage:
        findings.append(
            Finding(
                rule_id="CCA-020",
                severity=Severity.MEDIUM,
                confidence=sensitivity.confidence,
                title="CDN-specific caching header may override standard Cache-Control",
                description=(
                    "A CDN/proxy-specific caching header is present alongside "
                    "indicators of potentially sensitive content. These headers "
                    "(Surrogate-Control, CDN-Cache-Control, Cloudflare-CDN-Cache-Control) "
                    "can instruct CDN edge nodes to cache a response independently of "
                    "the standard Cache-Control header, which may not be obvious from "
                    "standard header review alone."
                ),
                evidence=evidence + list(sensitivity.reasons),
                affected_headers=list(present.keys()),
                why_it_matters=(
                    "CDN-specific directives are easy to overlook during review and "
                    "can silently widen caching scope beyond what Cache-Control alone "
                    "implies."
                ),
                recommendation=(
                    "Review CDN/edge configuration to ensure directives applied to "
                    "this endpoint match its sensitivity. " + sev.REMEDIATION_REVIEW_SHARED_CACHE
                ),
                category="cdn",
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="CCA-021",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="CDN-specific caching header detected",
                description=(
                    "A CDN/proxy-specific caching header was detected. No strong "
                    "sensitive-content indicators were present, but it is worth "
                    "confirming this configuration is intentional."
                ),
                evidence=evidence,
                affected_headers=list(present.keys()),
                why_it_matters="Awareness item: CDN headers can diverge from standard Cache-Control behavior.",
                recommendation="No action required if this configuration is intentional.",
                category="cdn",
            )
        )

    return findings
