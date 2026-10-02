"""
Analyzer orchestration: ties together parsing, sensitivity heuristics,
the rule engine, and risk scoring into a single `AnalysisResult`.
"""
from __future__ import annotations

from cache_analyzer.context import AnalysisContext
from cache_analyzer.models import AnalysisResult, HttpResponse, ScanMetadata
from cache_analyzer.parser import build_cache_policy
from cache_analyzer.rules import run_all_rules
from cache_analyzer.scoring import assess_sensitivity, compute_risk_level


def analyze_response(
    response: HttpResponse,
    metadata: ScanMetadata | None = None,
    body_analysis_enabled: bool = False,
) -> AnalysisResult:
    """Run the full analysis pipeline against a normalized HttpResponse."""
    metadata = metadata or ScanMetadata()
    metadata.body_analysis_enabled = body_analysis_enabled

    cache_policy = build_cache_policy(response.headers)
    sensitivity = assess_sensitivity(response, body_analysis_enabled=body_analysis_enabled)

    context = AnalysisContext(response=response, cache_policy=cache_policy, sensitivity=sensitivity)
    findings = run_all_rules(context)
    risk_level = compute_risk_level(findings)

    return AnalysisResult(
        target=response.url,
        response=response,
        cache_policy=cache_policy,
        sensitivity=sensitivity,
        findings=findings,
        risk_level=risk_level,
        metadata=metadata,
    )
