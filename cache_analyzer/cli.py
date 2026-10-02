"""
Command-line interface for Cache-Control Analyzer, built with Typer.

Commands:
    analyze   Analyze a single target (URL, raw response, headers file, or JSON).
    batch     Analyze multiple authorized URLs from a file, concurrently.
    parse     Parse and display a raw Cache-Control header value.
    rules     List all rule IDs known to the engine.
    report    Convert a previously saved JSON analysis result into another format.
    version   Show version and branding/support information.
"""
from __future__ import annotations

import concurrent.futures
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional

import typer

from cache_analyzer import (
    AUTHORIZED_USE_NOTICE,
    BANNER,
    FOOTER_TEXT,
    __author__,
    __support_url__,
    __title__,
    __version__,
    __youtube_url__,
)
from cache_analyzer.analyzer import analyze_response
from cache_analyzer.config import AppConfig
from cache_analyzer.fetcher import FetchError, fetch_from_config
from cache_analyzer.logger import get_logger
from cache_analyzer.models import Report, ScanMetadata
from cache_analyzer.parser import (
    parse_cache_control,
    parse_headers_file,
    parse_json_response_file,
    parse_raw_response_file,
)
from cache_analyzer.reporter import SUPPORTED_FORMATS, render_report, render_terminal
from cache_analyzer.rules.registry import RULES
from cache_analyzer.utils.validators import ValidationError, is_private_host, safe_output_path, validate_url

app = typer.Typer(
    name="cache-analyzer",
    help=f"{__title__} -- passive HTTP caching security analysis. {AUTHORIZED_USE_NOTICE}",
    add_completion=False,
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        _print_version()
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """Cache-Control Analyzer -- passive HTTP caching security analysis."""


def _print_version() -> None:
    typer.echo(BANNER)
    typer.echo(f"{__title__} v{__version__}")
    typer.echo(AUTHORIZED_USE_NOTICE)
    typer.echo("")
    typer.echo(FOOTER_TEXT)
    typer.echo(f"YouTube URL: {__youtube_url__}")
    typer.echo(f"Support URL: {__support_url__}")


def _build_config(
    timeout: float,
    user_agent: str,
    follow_redirects: bool,
    max_redirects: int,
    insecure: bool,
    verbose: bool,
    no_body: bool,
) -> AppConfig:
    config = AppConfig(
        timeout_seconds=timeout,
        user_agent=user_agent,
        follow_redirects=follow_redirects,
        max_redirects=max_redirects,
        insecure=insecure,
        verbose=verbose,
        no_body=no_body,
    )
    return config.clamp()


def _write_output(content: str, output: Optional[str], fmt: str) -> None:
    if output:
        path = safe_output_path(output)
        Path(path).write_text(content, encoding="utf-8")
        typer.echo(f"Report written to: {path}")
    else:
        typer.echo(content)


def _warn_if_private(url: str) -> None:
    if is_private_host(url):
        typer.secho(
            f"Warning: '{url}' resolves to a private/loopback-looking host. "
            "Ensure you are authorized to test this target.",
            fg=typer.colors.YELLOW,
            err=True,
        )


@app.command()
def analyze(
    url: Optional[str] = typer.Argument(None, help="Target URL to analyze (requires authorization)."),
    response: Optional[str] = typer.Option(None, "--response", help="Path to a raw saved HTTP response file."),
    headers: Optional[str] = typer.Option(None, "--headers", help="Path to a plain-text headers file."),
    json_input: Optional[str] = typer.Option(None, "--json", help="Path to a JSON response description file."),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds."),
    user_agent: str = typer.Option("CacheControlAnalyzer/1.0", "--user-agent", help="User-Agent header to send."),
    follow_redirects: bool = typer.Option(True, "--follow-redirects/--no-follow-redirects", help="Follow HTTP redirects."),
    max_redirects: int = typer.Option(5, "--max-redirects", help="Maximum number of redirects to follow."),
    fmt: str = typer.Option("terminal", "--format", "-f", help=f"Output format: {', '.join(SUPPORTED_FORMATS)}"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write report to this file instead of stdout."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
    insecure: bool = typer.Option(False, "--insecure", help="Disable TLS certificate verification (lab/testing only)."),
    no_body: bool = typer.Option(False, "--no-body", help="Do not fetch/analyze the response body."),
) -> None:
    """Analyze a single target: a URL, raw response file, headers file, or JSON file."""
    logger = get_logger("DEBUG" if verbose else "INFO")
    modes_provided = sum(bool(x) for x in (url, response, headers, json_input))

    if modes_provided == 0:
        typer.secho("Error: provide a URL or one of --response/--headers/--json.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    if modes_provided > 1:
        typer.secho("Error: provide only one input mode at a time.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    if fmt.lower() not in SUPPORTED_FORMATS:
        typer.secho(f"Error: unsupported format '{fmt}'.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    typer.secho(AUTHORIZED_USE_NOTICE, fg=typer.colors.YELLOW, err=True)

    try:
        if url:
            validate_url(url)
            _warn_if_private(url)
            config = _build_config(timeout, user_agent, follow_redirects, max_redirects, insecure, verbose, no_body)
            http_response = fetch_from_config(url, config)
            metadata = ScanMetadata(
                mode="url",
                insecure_tls=config.insecure,
                followed_redirects=config.follow_redirects,
                max_redirects=config.max_redirects,
                timeout_seconds=config.timeout_seconds,
                user_agent=config.user_agent,
                max_body_bytes=config.max_body_bytes,
            )
            body_analysis_enabled = not config.no_body
        elif response:
            http_response = parse_raw_response_file(response)
            metadata = ScanMetadata(mode="raw_response")
            body_analysis_enabled = not no_body
        elif headers:
            http_response = parse_headers_file(headers)
            metadata = ScanMetadata(mode="headers_file")
            body_analysis_enabled = False
        else:
            http_response = parse_json_response_file(json_input)
            metadata = ScanMetadata(mode="json")
            body_analysis_enabled = not no_body
    except (ValidationError, FetchError) as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    result = analyze_response(http_response, metadata=metadata, body_analysis_enabled=body_analysis_enabled)
    report = Report(results=[result])

    if fmt.lower() == "terminal":
        render_terminal(report)
        if output:
            typer.secho("Note: terminal format cannot be written to a file; use --format json/html/csv/markdown.", fg=typer.colors.YELLOW)
    else:
        content = render_report(report, fmt)
        _write_output(content, output, fmt)

    if result.risk_level.value == "HIGH":
        raise typer.Exit(code=3)


@app.command()
def batch(
    urls_file: str = typer.Argument(..., help="Path to a text file with one authorized URL per line."),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout in seconds."),
    user_agent: str = typer.Option("CacheControlAnalyzer/1.0", "--user-agent", help="User-Agent header to send."),
    follow_redirects: bool = typer.Option(True, "--follow-redirects/--no-follow-redirects"),
    max_redirects: int = typer.Option(5, "--max-redirects"),
    fmt: str = typer.Option("terminal", "--format", "-f", help=f"Output format: {', '.join(SUPPORTED_FORMATS)}"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    insecure: bool = typer.Option(False, "--insecure"),
    no_body: bool = typer.Option(False, "--no-body"),
    workers: int = typer.Option(5, "--workers", "-w", help="Concurrent worker count."),
    rate_limit: float = typer.Option(5.0, "--rate-limit", help="Maximum requests per second across all workers."),
    retries: int = typer.Option(2, "--retries", help="Retries for transient network errors."),
) -> None:
    """Analyze multiple authorized URLs concurrently."""
    get_logger("DEBUG" if verbose else "INFO")

    try:
        validate_file_path_arg = Path(urls_file)
        if not validate_file_path_arg.is_file():
            raise ValidationError(f"File not found: {urls_file}")
        raw_lines = validate_file_path_arg.read_text(encoding="utf-8").splitlines()
    except (OSError, ValidationError) as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    urls = [line.strip() for line in raw_lines if line.strip() and not line.strip().startswith("#")]
    if not urls:
        typer.secho("Error: no URLs found in input file.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    for u in urls:
        try:
            validate_url(u)
        except ValidationError as exc:
            typer.secho(f"Error: invalid URL '{u}': {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        _warn_if_private(u)

    typer.secho(AUTHORIZED_USE_NOTICE, fg=typer.colors.YELLOW, err=True)

    config = _build_config(timeout, user_agent, follow_redirects, max_redirects, insecure, verbose, no_body)
    config.workers = min(max(workers, 1), 32)
    config.rate_limit_per_sec = min(max(rate_limit, 0.1), 50.0)
    config.retries = min(max(retries, 0), 5)

    rate_lock = threading.Lock()
    min_interval = 1.0 / config.rate_limit_per_sec
    last_request_time = [0.0]

    def throttled_fetch_and_analyze(target_url: str):
        with rate_lock:
            now = time.monotonic()
            wait = min_interval - (now - last_request_time[0])
            if wait > 0:
                time.sleep(wait)
            last_request_time[0] = time.monotonic()
        try:
            http_response = fetch_from_config(target_url, config)
            metadata = ScanMetadata(
                mode="url",
                insecure_tls=config.insecure,
                followed_redirects=config.follow_redirects,
                max_redirects=config.max_redirects,
                timeout_seconds=config.timeout_seconds,
                user_agent=config.user_agent,
                max_body_bytes=config.max_body_bytes,
            )
            return analyze_response(http_response, metadata=metadata, body_analysis_enabled=not config.no_body)
        except FetchError as exc:
            typer.secho(f"Warning: failed to analyze {target_url}: {exc}", fg=typer.colors.YELLOW, err=True)
            return None

    results = []
    interrupted = False
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.workers) as executor:
            future_to_url = {executor.submit(throttled_fetch_and_analyze, u): u for u in urls}
            completed = 0
            for future in concurrent.futures.as_completed(future_to_url):
                completed += 1
                target = future_to_url[future]
                result = future.result()
                if result is not None:
                    results.append(result)
                typer.secho(f"[{completed}/{len(urls)}] analyzed {target}", err=True)
    except KeyboardInterrupt:
        interrupted = True
        typer.secho("\nInterrupted by user -- reporting partial results.", fg=typer.colors.YELLOW, err=True)

    report = Report(results=results)

    if fmt.lower() == "terminal":
        render_terminal(report)
    else:
        content = render_report(report, fmt)
        _write_output(content, output, fmt)

    if interrupted:
        raise typer.Exit(code=130)


@app.command()
def parse(
    value: str = typer.Argument(..., help="Raw Cache-Control header value to parse, e.g. 'public, max-age=600'."),
) -> None:
    """Parse and display the directives within a Cache-Control header value."""
    directives = parse_cache_control(value)
    if not directives:
        typer.echo("No directives parsed.")
        raise typer.Exit(code=0)
    typer.echo(f"Parsed {len(directives)} directive(s):\n")
    for name, param in directives.items():
        if param is None:
            typer.echo(f"  {name}")
        else:
            typer.echo(f"  {name} = {param}")


@app.command()
def rules() -> None:
    """List all rule IDs known to the engine, with default severity and title."""
    typer.echo(f"{'Rule ID':<10} {'Severity':<14} {'Category':<18} Title")
    typer.echo("-" * 90)
    for rule in RULES:
        typer.echo(f"{rule.rule_id:<10} {rule.default_severity:<14} {rule.category:<18} {rule.title}")


@app.command()
def report(
    input_json: str = typer.Argument(..., help="Path to a JSON report previously produced by 'analyze'/'batch'."),
    fmt: str = typer.Option("html", "--format", "-f", help="Target output format: json, csv, html, markdown."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write converted report to this file."),
) -> None:
    """Convert a previously saved JSON analysis report into another format."""
    try:
        content = Path(input_json).read_text(encoding="utf-8")
        report_obj = Report.model_validate_json(content)
    except Exception as exc:  # noqa: BLE001
        typer.secho(f"Error reading report: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    if fmt.lower() not in SUPPORTED_FORMATS:
        typer.secho(f"Error: unsupported format '{fmt}'.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    rendered = render_report(report_obj, fmt) if fmt.lower() != "terminal" else None
    if rendered is None:
        render_terminal(report_obj)
    else:
        _write_output(rendered, output, fmt)


@app.command()
def version() -> None:
    """Show version, authorized-use notice, and creator/support information."""
    _print_version()


@app.command()
def gui(
    host: str = typer.Option("127.0.0.1", "--host", help="Host/interface to bind the GUI server to."),
    port: int = typer.Option(8787, "--port", help="Port to serve the GUI on."),
) -> None:
    """Launch the optional local web-based GUI (requires 'pip install flask')."""
    try:
        from cache_analyzer.webgui import main as run_gui
    except ImportError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.secho(AUTHORIZED_USE_NOTICE, fg=typer.colors.YELLOW, err=True)
    typer.echo(f"Starting Cache-Control Analyzer GUI on http://{host}:{port}")
    run_gui(host=host, port=port)


if __name__ == "__main__":
    app()
