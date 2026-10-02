"""
Static rule registry used for documentation and the `rules` CLI command.

This is metadata only -- the actual detection logic lives in each rule
module. Keeping a static registry makes it easy to list every possible
rule ID (including ones that may not fire during a quick test) without
executing the full engine.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    category: str
    default_severity: str
    title: str


RULES: List[RuleMeta] = [
    RuleMeta("CCA-001", "sensitive_content", "HIGH", "Potentially sensitive response is publicly cacheable"),
    RuleMeta("CCA-002", "sensitive_content", "HIGH", "Potentially sensitive response appears cacheable by shared caches"),
    RuleMeta("CCA-003", "sensitive_content", "MEDIUM", "Potentially sensitive response is missing a Cache-Control header"),
    RuleMeta("CCA-004", "sensitive_content", "MEDIUM", "Long max-age on potentially sensitive, non-private response"),
    RuleMeta("CCA-005", "sensitive_content", "MEDIUM", "s-maxage present on potentially user-specific content"),
    RuleMeta("CCA-006", "sensitive_content", "INFORMATIONAL", "Explicit no-store directive on potentially sensitive content"),
    RuleMeta("CCA-007", "sensitive_content", "LOW", "Private caching directive limits exposure on potentially sensitive content"),
    RuleMeta("CCA-008", "sensitive_content", "INFORMATIONAL", "Short-lived cache configuration observed"),
    RuleMeta("CCA-009", "sensitive_content", "INFORMATIONAL", "No sensitive-content indicators detected"),
    RuleMeta("CCA-010", "cache_control", "LOW", "Conflicting 'public' and 'private' directives"),
    RuleMeta("CCA-011", "cache_control", "LOW", "'no-store' combined with max-age/s-maxage"),
    RuleMeta("CCA-012", "cache_control", "INFORMATIONAL", "'Vary: *' disables effective caching"),
    RuleMeta("CCA-013", "cache_control", "INFORMATIONAL", "'immutable' used with a short max-age"),
    RuleMeta("CCA-014", "cache_control", "LOW", "Malformed numeric directive value"),
    RuleMeta("CCA-020", "cdn", "MEDIUM", "CDN-specific caching header may override standard Cache-Control"),
    RuleMeta("CCA-021", "cdn", "INFORMATIONAL", "CDN-specific caching header detected"),
    RuleMeta("CCA-030", "cookies", "MEDIUM", "Session-related cookie on shared-cacheable response without cache-key discrimination"),
    RuleMeta("CCA-031", "cookies", "LOW", "Session-related cookie missing Secure/HttpOnly while response may be cached"),
    RuleMeta("CCA-040", "authentication", "HIGH", "Authenticated request response explicitly permits shared caching"),
    RuleMeta("CCA-041", "authentication", "INFORMATIONAL", "Authenticated request without explicit shared-cache override"),
]
