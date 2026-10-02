"""
Typed data models for Cache-Control Analyzer.

All structured data that flows through the analyzer is represented with
Pydantic models so that it can be validated, serialized, and reported
on consistently (JSON, CSV, HTML, Markdown, terminal).
"""
from __future__ import annotations

import enum
import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, enum.Enum):
    """Severity levels used across the rule engine."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFORMATIONAL"

    @property
    def rank(self) -> int:
        order = {
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return order[self]


class Confidence(str, enum.Enum):
    """Confidence levels for a given finding."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class SensitivityLevel(str, enum.Enum):
    """Likelihood that a response contains sensitive content."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CookieInfo(BaseModel):
    """Parsed representation of a single Set-Cookie header value."""

    name: str
    raw: str
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None
    max_age: Optional[int] = None
    expires: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None

    def looks_session_related(self) -> bool:
        lowered = self.name.lower()
        keywords = (
            "session",
            "sess",
            "auth",
            "token",
            "jwt",
            "sid",
            "login",
            "user",
            "account",
        )
        return any(k in lowered for k in keywords)


class CachePolicy(BaseModel):
    """Normalized representation of an HTTP response's caching policy."""

    raw_cache_control: Optional[str] = None
    directives: Dict[str, Optional[str]] = Field(default_factory=dict)

    pragma: Optional[str] = None
    expires: Optional[str] = None
    age: Optional[int] = None
    etag: Optional[str] = None
    vary: Optional[str] = None
    last_modified: Optional[str] = None
    surrogate_control: Optional[str] = None
    cdn_cache_control: Optional[str] = None
    cloudflare_cdn_cache_control: Optional[str] = None

    def has_directive(self, name: str) -> bool:
        return name.lower() in self.directives

    def directive_value(self, name: str) -> Optional[str]:
        return self.directives.get(name.lower())

    def max_age_seconds(self) -> Optional[int]:
        val = self.directive_value("max-age")
        if val is None:
            return None
        try:
            return int(val)
        except (TypeError, ValueError):
            return None

    def s_maxage_seconds(self) -> Optional[int]:
        val = self.directive_value("s-maxage")
        if val is None:
            return None
        try:
            return int(val)
        except (TypeError, ValueError):
            return None

    @property
    def is_public(self) -> bool:
        return self.has_directive("public")

    @property
    def is_private(self) -> bool:
        return self.has_directive("private")

    @property
    def is_no_store(self) -> bool:
        return self.has_directive("no-store")

    @property
    def is_no_cache(self) -> bool:
        return self.has_directive("no-cache")

    @property
    def is_immutable(self) -> bool:
        return self.has_directive("immutable")

    @property
    def shared_cache_permitted(self) -> bool:
        """Heuristic: could a shared cache (proxy/CDN) legally store this?"""
        if self.is_no_store:
            return False
        if self.is_private and self.s_maxage_seconds() is None:
            return False
        if self.is_public:
            return True
        if self.s_maxage_seconds() is not None:
            return True
        if self.cdn_cache_control or self.surrogate_control or self.cloudflare_cdn_cache_control:
            return True
        if self.raw_cache_control is None:
            # No explicit Cache-Control header -- many caches default to
            # heuristic freshness for cacheable status codes.
            return True
        return False


class RedirectHop(BaseModel):
    """A single hop in a redirect chain."""

    url: str
    status_code: int


class HttpResponse(BaseModel):
    """Normalized HTTP response used as analyzer input."""

    url: str
    final_url: Optional[str] = None
    status_code: int = 0
    http_version: Optional[str] = None
    reason: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    raw_header_lines: List[str] = Field(default_factory=list)
    body: Optional[str] = None
    body_truncated: bool = False
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    server: Optional[str] = None
    response_time_seconds: Optional[float] = None
    redirect_chain: List[RedirectHop] = Field(default_factory=list)
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    cookies: List[CookieInfo] = Field(default_factory=list)
    source: str = "url"  # url | raw_response | headers_file | json

    def get_header(self, name: str) -> Optional[str]:
        """Case-insensitive header lookup."""
        name_lower = name.lower()
        for key, value in self.headers.items():
            if key.lower() == name_lower:
                return value
        return None

    def has_set_cookie(self) -> bool:
        return bool(self.cookies) or self.get_header("set-cookie") is not None

    def has_authorization_header(self) -> bool:
        return self.get_header("authorization") is not None


class Finding(BaseModel):
    """A single structured finding produced by a rule."""

    rule_id: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    evidence: List[str] = Field(default_factory=list)
    affected_headers: List[str] = Field(default_factory=list)
    why_it_matters: str = ""
    recommendation: str = ""
    category: str = "general"


class RuleResult(BaseModel):
    """Return value of an individual rule function."""

    findings: List[Finding] = Field(default_factory=list)


class ScanMetadata(BaseModel):
    """Metadata describing the context of a scan/analysis run."""

    tool: str = "Cache-Control Analyzer"
    version: str = "1.0.0"
    scanned_at: float = Field(default_factory=time.time)
    mode: str = "url"
    insecure_tls: bool = False
    followed_redirects: bool = False
    max_redirects: int = 5
    timeout_seconds: float = 10.0
    user_agent: Optional[str] = None
    body_analysis_enabled: bool = False
    max_body_bytes: int = 0


class SensitivityAssessment(BaseModel):
    """Result of the sensitive-content heuristic engine."""

    level: SensitivityLevel = SensitivityLevel.NONE
    confidence: Confidence = Confidence.LOW
    reasons: List[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Full result of analyzing a single HTTP response."""

    target: str
    response: HttpResponse
    cache_policy: CachePolicy
    sensitivity: SensitivityAssessment
    findings: List[Finding] = Field(default_factory=list)
    risk_level: Severity = Severity.INFO
    metadata: ScanMetadata = Field(default_factory=ScanMetadata)

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


class Report(BaseModel):
    """Top-level report, potentially covering multiple analysis results."""

    generated_at: float = Field(default_factory=time.time)
    tool: str = "Cache-Control Analyzer"
    version: str = "1.0.0"
    results: List[AnalysisResult] = Field(default_factory=list)

    @property
    def overall_risk(self) -> Severity:
        if not self.results:
            return Severity.INFO
        return max((r.risk_level for r in self.results), key=lambda s: s.rank)

    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.results)

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for r in self.results:
            for f in r.findings:
                counts[f.severity.value] += 1
        return counts
