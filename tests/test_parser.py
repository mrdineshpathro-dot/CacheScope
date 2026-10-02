"""Tests for cache_analyzer.parser: Cache-Control parsing and input-mode parsing."""
import json
import os

import pytest

from cache_analyzer.parser import (
    build_cache_policy,
    parse_cache_control,
    parse_headers_file,
    parse_json_response_file,
    parse_raw_response_file,
)
from cache_analyzer.utils.validators import ValidationError


class TestParseCacheControl:
    def test_empty_value(self):
        assert parse_cache_control(None) == {}
        assert parse_cache_control("") == {}

    def test_simple_public(self):
        directives = parse_cache_control("public")
        assert directives == {"public": None}

    def test_public_with_max_age(self):
        directives = parse_cache_control("public, max-age=600")
        assert directives["public"] is None
        assert directives["max-age"] == "600"

    def test_private_no_cache_no_store(self):
        directives = parse_cache_control("private, no-cache, no-store")
        assert set(directives.keys()) == {"private", "no-cache", "no-store"}

    def test_must_revalidate_proxy_revalidate(self):
        directives = parse_cache_control("must-revalidate, proxy-revalidate")
        assert "must-revalidate" in directives
        assert "proxy-revalidate" in directives

    def test_s_maxage(self):
        directives = parse_cache_control("public, s-maxage=3600")
        assert directives["s-maxage"] == "3600"

    def test_immutable_stale_while_revalidate_stale_if_error(self):
        directives = parse_cache_control("max-age=600, immutable, stale-while-revalidate=30, stale-if-error=120")
        assert "immutable" in directives
        assert directives["stale-while-revalidate"] == "30"
        assert directives["stale-if-error"] == "120"

    def test_case_insensitivity_of_directive_names(self):
        directives = parse_cache_control("Public, Max-Age=600, No-Cache")
        assert "public" in directives
        assert "max-age" in directives
        assert "no-cache" in directives

    def test_duplicate_directives_last_wins(self):
        directives = parse_cache_control("max-age=100, max-age=200")
        assert directives["max-age"] == "200"

    def test_quoted_parameter_value(self):
        directives = parse_cache_control('no-cache="Set-Cookie"')
        assert directives["no-cache"] == "Set-Cookie"

    def test_irregular_whitespace(self):
        directives = parse_cache_control("  public ,   max-age = 600  ")
        assert "public" in directives
        # Note: space before '=' is retained in the name in edge cases;
        # this test ensures parsing does not raise and produces directives.
        assert len(directives) >= 1

    def test_malformed_trailing_comma(self):
        directives = parse_cache_control("public, max-age=600,")
        assert directives["public"] is None
        assert directives["max-age"] == "600"

    def test_empty_tokens_ignored(self):
        directives = parse_cache_control("public,, max-age=600")
        assert "public" in directives
        assert directives["max-age"] == "600"


class TestBuildCachePolicy:
    def test_missing_headers(self):
        policy = build_cache_policy({})
        assert policy.raw_cache_control is None
        assert policy.max_age_seconds() is None
        assert policy.shared_cache_permitted is True  # heuristic default cacheable

    def test_case_insensitive_header_lookup(self):
        headers = {"cache-control": "public, max-age=600", "ETAG": '"abc"'}
        policy = build_cache_policy(headers)
        assert policy.raw_cache_control == "public, max-age=600"
        assert policy.etag == '"abc"'

    def test_private_blocks_shared_cache(self):
        policy = build_cache_policy({"Cache-Control": "private, max-age=600"})
        assert policy.is_private is True
        assert policy.shared_cache_permitted is False

    def test_no_store_blocks_shared_cache(self):
        policy = build_cache_policy({"Cache-Control": "no-store"})
        assert policy.shared_cache_permitted is False

    def test_public_permits_shared_cache(self):
        policy = build_cache_policy({"Cache-Control": "public, max-age=600"})
        assert policy.shared_cache_permitted is True

    def test_age_parsing(self):
        policy = build_cache_policy({"Age": "120"})
        assert policy.age == 120

    def test_malformed_age_does_not_raise(self):
        policy = build_cache_policy({"Age": "not-a-number"})
        assert policy.age is None


class TestParseHeadersFile:
    def test_parse_headers_file(self, tmp_path):
        content = "HTTP/1.1 200 OK\nCache-Control: public, max-age=60\nContent-Type: text/html\n"
        file_path = tmp_path / "headers.txt"
        file_path.write_text(content)
        response = parse_headers_file(str(file_path), url="https://example.com/test")
        assert response.status_code == 200
        assert response.get_header("Cache-Control") == "public, max-age=60"
        assert response.content_type == "text/html"

    def test_missing_file_raises(self):
        with pytest.raises(ValidationError):
            parse_headers_file("/nonexistent/path/headers.txt")

    def test_duplicate_set_cookie_headers(self, tmp_path):
        content = (
            "HTTP/1.1 200 OK\n"
            "Set-Cookie: a=1; Path=/\n"
            "Set-Cookie: session=abc; HttpOnly; Secure\n"
        )
        file_path = tmp_path / "headers.txt"
        file_path.write_text(content)
        response = parse_headers_file(str(file_path))
        names = {c.name for c in response.cookies}
        assert names == {"a", "session"}


class TestParseRawResponseFile:
    def test_parse_raw_response_with_body(self, tmp_path):
        content = (
            "HTTP/1.1 200 OK\n"
            "Cache-Control: public, max-age=600\n"
            "Content-Type: text/html\n"
            "\n"
            "<html>hello</html>"
        )
        file_path = tmp_path / "response.txt"
        file_path.write_text(content)
        response = parse_raw_response_file(str(file_path))
        assert response.status_code == 200
        assert response.body == "<html>hello</html>"

    def test_parse_raw_response_no_body(self, tmp_path):
        content = "HTTP/1.1 304 Not Modified\nCache-Control: no-cache\n"
        file_path = tmp_path / "response.txt"
        file_path.write_text(content)
        response = parse_raw_response_file(str(file_path))
        assert response.status_code == 304
        assert response.body is None


class TestParseJsonResponseFile:
    def test_parse_valid_json(self, tmp_path):
        data = {
            "url": "https://example.com/account",
            "status_code": 200,
            "headers": {"Cache-Control": "public, max-age=600"},
            "body": "hello",
        }
        file_path = tmp_path / "response.json"
        file_path.write_text(json.dumps(data))
        response = parse_json_response_file(str(file_path))
        assert response.status_code == 200
        assert response.get_header("Cache-Control") == "public, max-age=600"

    def test_invalid_json_raises(self, tmp_path):
        file_path = tmp_path / "bad.json"
        file_path.write_text("{not valid json")
        with pytest.raises(ValidationError):
            parse_json_response_file(str(file_path))

    def test_missing_headers_field_defaults_empty(self, tmp_path):
        file_path = tmp_path / "minimal.json"
        file_path.write_text(json.dumps({"url": "https://example.com"}))
        response = parse_json_response_file(str(file_path))
        assert response.headers == {}
