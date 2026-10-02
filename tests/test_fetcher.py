"""Tests for cache_analyzer.fetcher: URL validation and safe-fetch behavior.

Network calls are mocked via httpx.MockTransport so these tests run
offline and deterministically.
"""
import httpx
import pytest

from cache_analyzer.fetcher import FetchError, FetchOptions, fetch_url
from cache_analyzer.utils.validators import ValidationError


def _patch_client(monkeypatch, handler):
    """Patch httpx.Client used inside fetch_url to use a MockTransport."""
    original_client = httpx.Client

    def client_factory(*args, **kwargs):
        kwargs.pop("verify", None)
        transport = httpx.MockTransport(handler)
        return original_client(transport=transport, **kwargs)

    monkeypatch.setattr(httpx, "Client", client_factory)


class TestValidation:
    def test_invalid_scheme_raises(self):
        with pytest.raises(ValidationError):
            fetch_url("ftp://example.com/file")

    def test_missing_host_raises(self):
        with pytest.raises(ValidationError):
            fetch_url("https://")

    def test_empty_url_raises(self):
        with pytest.raises(ValidationError):
            fetch_url("")


class TestMethodSafety:
    def test_post_method_rejected(self):
        with pytest.raises(ValidationError):
            fetch_url("https://example.com", FetchOptions(method="POST"))

    def test_delete_method_rejected(self):
        with pytest.raises(ValidationError):
            fetch_url("https://example.com", FetchOptions(method="DELETE"))


class TestFetchSuccess:
    def test_basic_fetch(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Cache-Control": "public, max-age=600", "Content-Type": "text/html"},
                text="<html>ok</html>",
            )

        _patch_client(monkeypatch, handler)
        result = fetch_url("https://example.com/account", FetchOptions(no_body=False, retries=0))
        assert result.status_code == 200
        assert result.get_header("Cache-Control") == "public, max-age=600"
        assert result.body == "<html>ok</html>"

    def test_no_body_skips_body(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>ok</html>")

        _patch_client(monkeypatch, handler)
        result = fetch_url("https://example.com/", FetchOptions(no_body=True, retries=0))
        assert result.body is None

    def test_redirect_chain_recorded(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            if str(request.url) == "https://example.com/old":
                return httpx.Response(302, headers={"Location": "https://example.com/new"})
            return httpx.Response(200, text="final")

        _patch_client(monkeypatch, handler)
        result = fetch_url("https://example.com/old", FetchOptions(no_body=False, follow_redirects=True, retries=0))
        assert result.status_code == 200
        assert len(result.redirect_chain) == 1
        assert result.redirect_chain[0].status_code == 302

    def test_timeout_raises_fetch_error(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("timed out", request=request)

        _patch_client(monkeypatch, handler)
        with pytest.raises(FetchError):
            fetch_url("https://example.com/", FetchOptions(retries=0))

    def test_body_truncated_when_oversized(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="A" * 1000)

        _patch_client(monkeypatch, handler)
        result = fetch_url("https://example.com/", FetchOptions(no_body=False, max_body_bytes=10, retries=0))
        assert result.body_truncated is True
        assert len(result.body) == 10
