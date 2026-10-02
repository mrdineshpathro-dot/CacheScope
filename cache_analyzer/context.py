"""
Shared analysis context passed to every rule.

Kept in its own module (rather than `models.py` or `analyzer.py`) to
avoid circular imports between the rule engine, the scoring module,
and the analyzer orchestrator.
"""
from __future__ import annotations

from dataclasses import dataclass

from cache_analyzer.models import CachePolicy, HttpResponse, SensitivityAssessment


@dataclass
class AnalysisContext:
    """Bundles everything a rule needs in order to produce findings."""

    response: HttpResponse
    cache_policy: CachePolicy
    sensitivity: SensitivityAssessment
