"""
Modular rule engine for Cache-Control Analyzer.

Each submodule exposes a `run(context) -> List[Finding]` function. This
package's `run_all_rules` aggregates every rule module's findings into a
single, de-duplicated, severity-sorted list.

Rule ID ranges (kept stable across releases so findings can be tracked):

    CCA-001 .. CCA-009   sensitive_content.py  (sensitivity x cache risk)
    CCA-010 .. CCA-019   cache_control.py      (directive-level issues)
    CCA-020 .. CCA-029   cdn.py                (CDN / shared-cache headers)
    CCA-030 .. CCA-039   cookies.py            (cookie-aware analysis)
    CCA-040 .. CCA-049   authentication.py     (auth-aware heuristics)
"""
from __future__ import annotations

from typing import List

from cache_analyzer.context import AnalysisContext
from cache_analyzer.models import Finding
from cache_analyzer.rules import authentication, cache_control, cdn, cookies, sensitive_content

_RULE_MODULES = (
    sensitive_content,
    cache_control,
    cdn,
    cookies,
    authentication,
)


def run_all_rules(context: AnalysisContext) -> List[Finding]:
    """Run every rule module against the given context and merge results."""
    findings: List[Finding] = []
    seen_ids = set()

    for module in _RULE_MODULES:
        module_findings = module.run(context)
        for finding in module_findings:
            # Guard against accidental rule-id collisions across modules.
            dedupe_key = (finding.rule_id, tuple(finding.evidence))
            if dedupe_key in seen_ids:
                continue
            seen_ids.add(dedupe_key)
            findings.append(finding)

    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id))
    return findings


__all__ = ["run_all_rules"]
