"""
Sensitive-content heuristics and the overall cache-risk decision model.

IMPORTANT: this module never claims certainty. URL patterns, headers,
and (optionally) a capped amount of body text are combined into a
*likelihood* with an associated confidence level. Callers must present
these as heuristics, not confirmed facts.
"""
from __future__ import annotations

import re
from typing import List, Tuple

from cache_analyzer.models import (
    AnalysisResult,
    Confidence,
    Finding,
    HttpResponse,
    SensitivityAssessment,
    SensitivityLevel,
    Severity,
)

# Heuristic URL path indicators. These never *prove* authentication or
# sensitivity on their own -- they only raise or lower a likelihood score.
_SENSITIVE_PATH_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"/account(s)?(/|$)", re.I), "URL path suggests an account page"),
    (re.compile(r"/profile(/|$)", re.I), "URL path suggests a user profile page"),
    (re.compile(r"/dashboard(/|$)", re.I), "URL path suggests a dashboard"),
    (re.compile(r"/settings(/|$)", re.I), "URL path suggests a settings page"),
    (re.compile(r"/admin(istrator)?(/|$)", re.I), "URL path suggests an administrative interface"),
    (re.compile(r"/user(s)?(/|$)", re.I), "URL path suggests user-specific content"),
    (re.compile(r"/session(s)?(/|$)", re.I), "URL path suggests session-related content"),
    (re.compile(r"/api/me(/|$)", re.I), "URL path suggests an authenticated 'current user' API endpoint"),
    (re.compile(r"/auth(entication)?(/|$)", re.I), "URL path suggests an authentication-related endpoint"),
    (re.compile(r"/login(/|$)", re.I), "URL path suggests a login page"),
    (re.compile(r"/logout(/|$)", re.I), "URL path suggests a logout endpoint"),
    (re.compile(r"/password-?reset(/|$)", re.I), "URL path suggests a password-reset flow"),
    (re.compile(r"/reset-?password(/|$)", re.I), "URL path suggests a password-reset flow"),
    (re.compile(r"/otp(/|$)", re.I), "URL path suggests an OTP / one-time-passcode flow"),
    (re.compile(r"/mfa(/|$)", re.I), "URL path suggests a multi-factor authentication flow"),
    (re.compile(r"/billing(/|$)", re.I), "URL path suggests billing/financial content"),
    (re.compile(r"/invoice(s)?(/|$)", re.I), "URL path suggests invoice/financial content"),
    (re.compile(r"/token(s)?(/|$)", re.I), "URL path suggests token-related content"),
]

# Body/content keyword indicators (only used when body analysis is enabled
# and a body is present). Matching is case-insensitive and capped to a
# configurable prefix of the body for performance/safety.
_SENSITIVE_BODY_KEYWORDS = [
    "password",
    "two-factor",
    "one-time code",
    "one time passcode",
    "otp",
    "verification code",
    "security code",
    "sign out",
    "log out",
    "my account",
    "my profile",
    "welcome back",
    "api_key",
    "api key",
    "session_id",
    "csrf",
    "authorization code",
    "social security",
    "ssn",
    "credit card",
    "account number",
]

_API_CONTENT_TYPES = ("application/json", "application/xml", "application/vnd.api+json")


def assess_sensitivity(response: HttpResponse, body_analysis_enabled: bool = False) -> SensitivityAssessment:
    """Produce a heuristic sensitivity assessment for an HTTP response.

    This NEVER asserts that sensitive data definitely exists. It
    aggregates weighted signals into a LOW/MEDIUM/HIGH likelihood plus a
    confidence level, and records every contributing reason so the
    report can explain itself.
    """
    reasons: List[str] = []
    score = 0

    # --- URL heuristics -------------------------------------------------
    path_hits = 0
    for pattern, reason in _SENSITIVE_PATH_PATTERNS:
        if pattern.search(response.url) or (response.final_url and pattern.search(response.final_url)):
            reasons.append(reason)
            path_hits += 1
    score += min(path_hits, 3) * 2  # cap contribution from URL alone

    # --- Auth signals -----------------------------------------------------
    if response.has_authorization_header():
        reasons.append("Request included an Authorization header")
        score += 3

    if response.has_set_cookie():
        session_cookies = [c for c in response.cookies if c.looks_session_related()]
        if session_cookies:
            names = ", ".join(c.name for c in session_cookies)
            reasons.append(f"Session/auth-like cookie(s) present: {names}")
            score += 3
        elif response.cookies:
            reasons.append("Set-Cookie header present")
            score += 1

    # --- Status code --------------------------------------------------
    if response.status_code in (401, 403):
        reasons.append(f"HTTP {response.status_code} suggests an authentication/authorization boundary")
        score += 1
    elif response.status_code == 200 and path_hits:
        reasons.append("Endpoint returned 200 OK while matching a sensitive URL pattern")
        score += 1

    # --- Content-Type --------------------------------------------------
    if response.content_type:
        ct = response.content_type.lower()
        if any(ct.startswith(api_ct) for api_ct in _API_CONTENT_TYPES):
            reasons.append(f"Content-Type '{response.content_type}' suggests an API response")
            score += 1

    # --- Optional body heuristics ---------------------------------------
    if body_analysis_enabled and response.body:
        lowered = response.body.lower()
        body_hits = [kw for kw in _SENSITIVE_BODY_KEYWORDS if kw in lowered]
        if body_hits:
            sample = ", ".join(sorted(set(body_hits))[:5])
            reasons.append(f"Response body contains sensitive-sounding keywords: {sample}")
            score += min(len(body_hits), 4)

    # --- Translate score into level/confidence --------------------------
    if score >= 7:
        level = SensitivityLevel.HIGH
        confidence = Confidence.MEDIUM if path_hits <= 1 else Confidence.HIGH
    elif score >= 4:
        level = SensitivityLevel.MEDIUM
        confidence = Confidence.MEDIUM
    elif score >= 1:
        level = SensitivityLevel.LOW
        confidence = Confidence.LOW
    else:
        level = SensitivityLevel.NONE
        confidence = Confidence.LOW

    if not reasons:
        reasons.append("No sensitive-content indicators were detected by the available heuristics.")

    return SensitivityAssessment(level=level, confidence=confidence, reasons=reasons)


def compute_risk_level(findings: List[Finding]) -> Severity:
    """Overall risk level for a result is the highest finding severity."""
    if not findings:
        return Severity.INFO
    return max((f.severity for f in findings), key=lambda s: s.rank)
