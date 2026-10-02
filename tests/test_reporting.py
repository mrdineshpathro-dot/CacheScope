"""Tests for cache_analyzer.reporter: JSON/CSV/HTML/Markdown report generation."""
import json

from cache_analyzer.analyzer import analyze_response
from cache_analyzer.models import HttpResponse, Report
from cache_analyzer.reporter import render_csv, render_html, render_json, render_markdown, render_report


def _sample_report() -> Report:
    resp = HttpResponse(
        url="https://example.com/account",
        final_url="https://example.com/account",
        status_code=200,
        headers={"Cache-Control": "public, max-age=600", "Content-Type": "text/html"},
    )
    result = analyze_response(resp)
    return Report(results=[result])


class TestJsonReport:
    def test_render_json_is_valid_json(self):
        report = _sample_report()
        output = render_json(report)
        data = json.loads(output)
        assert "results" in data
        assert data["results"][0]["target"] == "https://example.com/account"

    def test_render_report_dispatch_json(self):
        report = _sample_report()
        output = render_report(report, "json")
        assert json.loads(output)


class TestCsvReport:
    def test_render_csv_has_header_and_rows(self):
        report = _sample_report()
        output = render_csv(report)
        lines = output.strip().splitlines()
        assert lines[0].startswith("target,status_code,rule_id")
        assert len(lines) > 1

    def test_render_csv_no_findings_case(self):
        resp = HttpResponse(url="https://example.com/blog", status_code=200)
        result = analyze_response(resp)
        # Force no findings scenario is unlikely (CCA-009 always fires for
        # non-sensitive pages); ensure CSV still renders without error.
        report = Report(results=[result])
        output = render_csv(report)
        assert "https://example.com/blog" in output


class TestHtmlReport:
    def test_render_html_contains_target_and_footer(self):
        report = _sample_report()
        output = render_html(report)
        assert "<html" in output.lower()
        assert "example.com/account" in output
        assert "buymeacoffee.com/mrdineshpathro" in output

    def test_render_html_escapes_content(self):
        resp = HttpResponse(
            url="https://example.com/<script>",
            status_code=200,
            headers={"Cache-Control": "public"},
        )
        result = analyze_response(resp)
        report = Report(results=[result])
        output = render_html(report)
        assert "<script>" not in output


class TestMarkdownReport:
    def test_render_markdown_contains_sections(self):
        report = _sample_report()
        output = render_markdown(report)
        assert "# Cache-Control Analyzer Report" in output
        assert "## https://example.com/account" in output

    def test_render_markdown_footer_present(self):
        report = _sample_report()
        output = render_markdown(report)
        assert "Mr Dinesh Pathro" in output


class TestRenderReportDispatch:
    def test_unsupported_format_raises(self):
        report = _sample_report()
        try:
            render_report(report, "yaml")
            assert False, "expected ValueError"
        except ValueError:
            pass
