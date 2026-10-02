"""
Report generation for Cache-Control Analyzer.

Supports terminal (rich), JSON, CSV, HTML, and Markdown output for both
single-target analyses and multi-target (batch) reports.
"""
from __future__ import annotations

import csv
import io
import json
from typing import List

from cache_analyzer import __author__, __support_url__, __version__, __youtube_url__, FOOTER_TEXT
from cache_analyzer.models import AnalysisResult, Report
from cache_analyzer.utils.formatting import (
    SEVERITY_HTML_COLORS,
    escape_html,
    human_bytes,
    human_seconds,
    truncate,
)

SUPPORTED_FORMATS = ("terminal", "json", "csv", "html", "markdown")


# ---------------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------------

def render_terminal(report: Report, console=None) -> None:
    """Render a report to the terminal using `rich` for nice formatting."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = console or Console()

    console.print(
        Panel.fit(
            "[bold]CACHE-CONTROL ANALYZER[/bold]",
            border_style="bright_blue",
        )
    )

    for result in report.results:
        _render_single_result_terminal(console, result)
        console.print()

    counts = report.counts_by_severity()
    summary = Table(title="Overall Summary", show_header=True, header_style="bold")
    summary.add_column("Targets")
    summary.add_column("Findings")
    summary.add_column("HIGH", style="red")
    summary.add_column("MEDIUM", style="yellow")
    summary.add_column("LOW", style="cyan")
    summary.add_column("INFO", style="grey62")
    summary.add_row(
        str(len(report.results)),
        str(report.total_findings()),
        str(counts["HIGH"]),
        str(counts["MEDIUM"]),
        str(counts["LOW"]),
        str(counts["INFORMATIONAL"]),
    )
    console.print(summary)
    console.print(f"[bold]Overall Risk Level:[/bold] {_risk_markup(report.overall_risk.value)}")
    console.rule()
    console.print(FOOTER_TEXT, style="dim")


def _risk_markup(level: str) -> str:
    color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFORMATIONAL": "grey62"}.get(level, "white")
    return f"[bold {color}]{level}[/bold {color}]"


def _render_single_result_terminal(console, result: AnalysisResult) -> None:
    from rich.table import Table

    resp = result.response
    policy = result.cache_policy

    console.rule(f"[bold]{result.target}[/bold]")
    meta_table = Table.grid(padding=(0, 2))
    meta_table.add_row("Target", result.target)
    meta_table.add_row("Status", f"{resp.status_code} {resp.reason or ''}".strip())
    meta_table.add_row("Content-Type", resp.content_type or "-")
    meta_table.add_row("Response", human_bytes(resp.content_length))
    meta_table.add_row("Time", human_seconds(resp.response_time_seconds))
    console.print(meta_table)

    console.print("\n[bold]Cache Policy[/bold]")
    console.print("\u2500" * 50)
    cache_table = Table.grid(padding=(0, 2))
    cache_table.add_row("Cache-Control", policy.raw_cache_control or "-")
    cache_table.add_row("Pragma", policy.pragma or "-")
    cache_table.add_row("Expires", policy.expires or "-")
    cache_table.add_row("Age", str(policy.age) if policy.age is not None else "-")
    cache_table.add_row("Vary", policy.vary or "-")
    cache_table.add_row("Set-Cookie", "Present" if resp.has_set_cookie() else "-")
    console.print(cache_table)

    console.print("\n[bold]Findings[/bold]")
    console.print("\u2500" * 50)
    if not result.findings:
        console.print("No findings.")
    for finding in result.findings:
        color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFORMATIONAL": "grey62"}.get(
            finding.severity.value, "white"
        )
        console.print(f"\n[bold {color}][{finding.severity.value}] {finding.rule_id}[/bold {color}]")
        console.print(finding.title)
        console.print(f"Confidence : {finding.confidence.value}")
        if finding.evidence:
            console.print("\nEvidence:")
            for ev in finding.evidence:
                console.print(f"  {ev}")
        if finding.recommendation:
            console.print("\nRecommendation:")
            console.print(f"  {finding.recommendation}")

    console.print("\n" + "\u2500" * 50)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def render_json(report: Report) -> str:
    return report.model_dump_json(indent=2)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def render_csv(report: Report) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "target",
            "status_code",
            "rule_id",
            "severity",
            "confidence",
            "title",
            "affected_headers",
            "evidence",
            "recommendation",
        ]
    )
    for result in report.results:
        if not result.findings:
            writer.writerow([result.target, result.response.status_code, "", "", "", "No findings", "", "", ""])
            continue
        for finding in result.findings:
            writer.writerow(
                [
                    result.target,
                    result.response.status_code,
                    finding.rule_id,
                    finding.severity.value,
                    finding.confidence.value,
                    finding.title,
                    "; ".join(finding.affected_headers),
                    " | ".join(finding.evidence),
                    finding.recommendation.replace("\n", " "),
                ]
            )
    return buf.getvalue()


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_HTML_TEMPLATE_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cache-Control Analyzer Report</title>
<style>
body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 2rem; background: #0f1115; color: #e6e6e6; }
h1 { color: #5dade2; }
.summary { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
.card { background: #1b1e26; border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; }
.card h3 { margin: 0; font-size: 0.85rem; color: #9aa5b1; text-transform: uppercase; }
.card p { margin: 0.25rem 0 0; font-size: 1.6rem; font-weight: bold; }
.target { background: #161920; border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }
.finding { border-left: 4px solid #555; background: #1b1e26; padding: 0.75rem 1rem; margin: 0.75rem 0; border-radius: 4px; }
.badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px; font-size: 0.75rem; font-weight: bold; color: white; margin-right: 0.5rem; }
pre { white-space: pre-wrap; background: #10131a; padding: 0.5rem 0.75rem; border-radius: 6px; }
footer { margin-top: 3rem; color: #9aa5b1; font-size: 0.85rem; border-top: 1px solid #2a2f3a; padding-top: 1rem; }
a { color: #5dade2; }
</style>
</head>
<body>
<h1>Cache-Control Analyzer Report</h1>
"""

_HTML_TEMPLATE_TAIL = """
<footer>
  {footer}<br>
  Support: <a href="{support_url}">{support_url}</a><br>
  YouTube: <a href="{youtube_url}">{youtube_url}</a>
</footer>
</body>
</html>
"""


def render_html(report: Report) -> str:
    counts = report.counts_by_severity()
    parts = [_HTML_TEMPLATE_HEAD]

    parts.append('<div class="summary">')
    parts.append(f'<div class="card"><h3>Targets</h3><p>{len(report.results)}</p></div>')
    parts.append(f'<div class="card"><h3>Findings</h3><p>{report.total_findings()}</p></div>')
    for sev_name in ("HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        color = SEVERITY_HTML_COLORS[sev_name]
        parts.append(
            f'<div class="card" style="border-top:3px solid {color};">'
            f"<h3>{sev_name}</h3><p>{counts[sev_name]}</p></div>"
        )
    parts.append("</div>")

    for result in report.results:
        parts.append('<div class="target">')
        parts.append(f"<h2>{escape_html(result.target)}</h2>")
        parts.append(
            f"<p><strong>Status:</strong> {result.response.status_code} "
            f"&nbsp; <strong>Risk:</strong> {result.risk_level.value} "
            f"&nbsp; <strong>Content-Type:</strong> {escape_html(result.response.content_type or '-')}</p>"
        )
        if not result.findings:
            parts.append("<p>No findings.</p>")
        for finding in result.findings:
            color = SEVERITY_HTML_COLORS.get(finding.severity.value, "#888")
            parts.append(f'<div class="finding" style="border-left-color:{color}">')
            parts.append(
                f'<span class="badge" style="background:{color}">{finding.severity.value}</span>'
                f"<strong>{escape_html(finding.rule_id)}</strong> &mdash; {escape_html(finding.title)}"
            )
            parts.append(f"<p>{escape_html(finding.description)}</p>")
            parts.append(f"<p><em>Confidence: {finding.confidence.value}</em></p>")
            if finding.evidence:
                parts.append("<pre>" + escape_html("\n".join(finding.evidence)) + "</pre>")
            if finding.recommendation:
                parts.append(f"<p><strong>Recommendation:</strong> {escape_html(finding.recommendation)}</p>")
            parts.append("</div>")
        parts.append("</div>")

    parts.append(
        _HTML_TEMPLATE_TAIL.format(
            footer=escape_html(f"Created by {__author__}"),
            support_url=__support_url__,
            youtube_url=__youtube_url__,
        )
    )
    return "".join(parts)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def render_markdown(report: Report) -> str:
    counts = report.counts_by_severity()
    lines: List[str] = []
    lines.append("# Cache-Control Analyzer Report\n")
    lines.append(f"**Targets analyzed:** {len(report.results)}  ")
    lines.append(f"**Total findings:** {report.total_findings()}  ")
    lines.append(f"**Overall risk level:** {report.overall_risk.value}\n")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev_name in ("HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        lines.append(f"| {sev_name} | {counts[sev_name]} |")
    lines.append("")

    for result in report.results:
        lines.append(f"## {result.target}\n")
        lines.append(f"- **Status:** {result.response.status_code}")
        lines.append(f"- **Risk Level:** {result.risk_level.value}")
        lines.append(f"- **Content-Type:** {result.response.content_type or '-'}")
        lines.append(f"- **Cache-Control:** `{result.cache_policy.raw_cache_control or '-'}`\n")

        if not result.findings:
            lines.append("_No findings._\n")
            continue

        for finding in result.findings:
            lines.append(f"### [{finding.severity.value}] {finding.rule_id} &mdash; {finding.title}\n")
            lines.append(f"**Confidence:** {finding.confidence.value}\n")
            lines.append(f"{finding.description}\n")
            if finding.affected_headers:
                lines.append(f"**Affected header(s):** {', '.join(finding.affected_headers)}\n")
            if finding.evidence:
                lines.append("**Evidence:**")
                lines.append("```")
                lines.extend(finding.evidence)
                lines.append("```")
            if finding.why_it_matters:
                lines.append(f"\n**Why it matters:** {finding.why_it_matters}\n")
            if finding.recommendation:
                lines.append(f"**Recommendation:** {finding.recommendation}\n")
        lines.append("")

    lines.append("---")
    lines.append(f"_{FOOTER_TEXT.replace(chr(10), '  ' + chr(10))}_")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def render_report(report: Report, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return render_json(report)
    if fmt == "csv":
        return render_csv(report)
    if fmt == "html":
        return render_html(report)
    if fmt in ("markdown", "md"):
        return render_markdown(report)
    raise ValueError(f"Unsupported format: {fmt}")
