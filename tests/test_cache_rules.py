"""Tests for the rule engine (cache_analyzer.rules.*)."""
from cache_analyzer.analyzer import analyze_response
from cache_analyzer.models import CookieInfo, HttpResponse
from cache_analyzer.parser import build_cache_policy
from cache_analyzer.scoring import assess_sensitivity


def _response(url="https://example.com/account", headers=None, status_code=200, cookies=None, body=None):
    return HttpResponse(
        url=url,
        final_url=url,
        status_code=status_code,
        headers=headers or {},
        cookies=cookies or [],
        body=body,
        content_type=(headers or {}).get("Content-Type"),
    )


class TestSensitiveContentRules:
    def test_high_risk_public_sensitive(self):
        resp = _response(
            url="https://example.com/account",
            headers={"Cache-Control": "public, max-age=600"},
            cookies=[CookieInfo(name="session_id", raw="session_id=abc", secure=True, http_only=True)],
        )
        result = analyze_response(resp)
        rule_ids = {f.rule_id for f in result.findings}
        assert "CCA-001" in rule_ids
        assert result.risk_level.value == "HIGH"

    def test_no_store_sensitive_is_informational(self):
        resp = _response(
            url="https://example.com/account",
            headers={"Cache-Control": "no-store"},
            cookies=[CookieInfo(name="session_id", raw="session_id=abc", secure=True, http_only=True)],
        )
        result = analyze_response(resp)
        high_findings = [f for f in result.findings if f.severity.value == "HIGH"]
        assert high_findings == []

    def test_non_sensitive_generic_page(self):
        resp = _response(
            url="https://example.com/blog/post-1",
            headers={"Cache-Control": "public, max-age=86400"},
        )
        result = analyze_response(resp)
        rule_ids = {f.rule_id for f in result.findings}
        assert "CCA-009" in rule_ids
        assert result.risk_level.value != "HIGH"

    def test_missing_cache_control_on_sensitive_page_is_medium(self):
        resp = _response(
            url="https://example.com/dashboard",
            headers={},
            cookies=[CookieInfo(name="auth_token", raw="auth_token=xyz", secure=True, http_only=True)],
        )
        result = analyze_response(resp)
        rule_ids = {f.rule_id for f in result.findings}
        assert "CCA-003" in rule_ids


class TestCacheControlDirectiveRules:
    def test_conflicting_public_private(self):
        resp = _response(url="https://example.com/x", headers={"Cache-Control": "public, private"})
        result = analyze_response(resp)
        assert "CCA-010" in {f.rule_id for f in result.findings}

    def test_malformed_max_age(self):
        resp = _response(url="https://example.com/x", headers={"Cache-Control": "max-age=notanumber"})
        result = analyze_response(resp)
        assert "CCA-014" in {f.rule_id for f in result.findings}

    def test_negative_max_age(self):
        resp = _response(url="https://example.com/x", headers={"Cache-Control": "max-age=-5"})
        result = analyze_response(resp)
        assert "CCA-014" in {f.rule_id for f in result.findings}

    def test_vary_star(self):
        resp = _response(url="https://example.com/x", headers={"Cache-Control": "public", "Vary": "*"})
        result = analyze_response(resp)
        assert "CCA-012" in {f.rule_id for f in result.findings}


class TestCdnRules:
    def test_cdn_header_with_sensitive_content(self):
        resp = _response(
            url="https://example.com/account",
            headers={"Cache-Control": "private", "Surrogate-Control": "max-age=3600"},
            cookies=[CookieInfo(name="session", raw="session=1", secure=True, http_only=True)],
        )
        result = analyze_response(resp)
        assert "CCA-020" in {f.rule_id for f in result.findings}


class TestCookieRules:
    def test_session_cookie_on_shared_cacheable_response(self):
        resp = _response(
            url="https://example.com/dashboard",
            headers={"Cache-Control": "public, max-age=600"},
            cookies=[CookieInfo(name="session_id", raw="session_id=abc; Secure; HttpOnly", secure=True, http_only=True)],
        )
        result = analyze_response(resp)
        assert "CCA-030" in {f.rule_id for f in result.findings}

    def test_session_cookie_missing_secure_httponly(self):
        resp = _response(
            url="https://example.com/dashboard",
            headers={"Cache-Control": "private"},
            cookies=[CookieInfo(name="session_id", raw="session_id=abc", secure=False, http_only=False)],
        )
        result = analyze_response(resp)
        assert "CCA-031" in {f.rule_id for f in result.findings}


class TestAuthenticationRules:
    def test_authorization_header_with_public_override(self):
        resp = _response(
            url="https://example.com/api/me",
            headers={"Cache-Control": "public, max-age=60", "Authorization": "Bearer sometoken"},
        )
        result = analyze_response(resp)
        assert "CCA-040" in {f.rule_id for f in result.findings}
        assert result.risk_level.value == "HIGH"

    def test_authorization_header_without_override_is_safe(self):
        resp = _response(
            url="https://example.com/api/me",
            headers={"Cache-Control": "no-store", "Authorization": "Bearer sometoken"},
        )
        result = analyze_response(resp)
        assert "CCA-041" in {f.rule_id for f in result.findings}
