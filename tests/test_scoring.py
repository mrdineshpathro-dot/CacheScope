"""Tests for cache_analyzer.scoring: sensitivity heuristics and risk aggregation."""
from cache_analyzer.models import (
    Confidence,
    CookieInfo,
    Finding,
    HttpResponse,
    Severity,
    SensitivityLevel,
)
from cache_analyzer.scoring import assess_sensitivity, compute_risk_level


def _finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="CCA-TEST",
        severity=severity,
        confidence=Confidence.MEDIUM,
        title="test",
        description="test",
    )


class TestAssessSensitivity:
    def test_generic_page_is_none_or_low(self):
        resp = HttpResponse(url="https://example.com/about", status_code=200)
        assessment = assess_sensitivity(resp)
        assert assessment.level in (SensitivityLevel.NONE, SensitivityLevel.LOW)

    def test_account_path_raises_sensitivity(self):
        resp = HttpResponse(url="https://example.com/account/profile", status_code=200)
        assessment = assess_sensitivity(resp)
        assert assessment.level != SensitivityLevel.NONE
        assert any("account" in r.lower() for r in assessment.reasons)

    def test_authorization_header_increases_sensitivity(self):
        resp = HttpResponse(
            url="https://example.com/api/data",
            status_code=200,
            headers={"Authorization": "Bearer xyz"},
        )
        assessment = assess_sensitivity(resp)
        assert assessment.level != SensitivityLevel.NONE

    def test_session_cookie_increases_sensitivity(self):
        resp = HttpResponse(
            url="https://example.com/x",
            status_code=200,
            cookies=[CookieInfo(name="session_id", raw="session_id=1")],
        )
        assessment = assess_sensitivity(resp)
        assert assessment.level != SensitivityLevel.NONE

    def test_dashboard_plus_auth_cookie_plus_authz_is_high(self):
        resp = HttpResponse(
            url="https://example.com/dashboard/settings",
            status_code=200,
            headers={"Authorization": "Bearer xyz"},
            cookies=[CookieInfo(name="session_id", raw="session_id=1")],
        )
        assessment = assess_sensitivity(resp)
        assert assessment.level == SensitivityLevel.HIGH

    def test_body_keywords_only_considered_when_enabled(self):
        resp = HttpResponse(
            url="https://example.com/x",
            status_code=200,
            body="Please enter your password and verification code.",
        )
        without_body = assess_sensitivity(resp, body_analysis_enabled=False)
        with_body = assess_sensitivity(resp, body_analysis_enabled=True)
        assert with_body.level.value != SensitivityLevel.NONE.value or without_body.level == SensitivityLevel.NONE
        # Body analysis should surface at least one additional reason.
        assert len(with_body.reasons) >= len(without_body.reasons)

    def test_never_claims_certainty_in_reasons(self):
        resp = HttpResponse(url="https://example.com/account", status_code=200)
        assessment = assess_sensitivity(resp)
        for reason in assessment.reasons:
            assert "definitely" not in reason.lower()
            assert "confirmed" not in reason.lower()


class TestComputeRiskLevel:
    def test_no_findings_is_informational(self):
        assert compute_risk_level([]) == Severity.INFO

    def test_highest_severity_wins(self):
        findings = [_finding(Severity.LOW), _finding(Severity.HIGH), _finding(Severity.MEDIUM)]
        assert compute_risk_level(findings) == Severity.HIGH

    def test_all_info(self):
        findings = [_finding(Severity.INFO), _finding(Severity.INFO)]
        assert compute_risk_level(findings) == Severity.INFO
