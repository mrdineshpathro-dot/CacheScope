# Cache-Control Analyzer

A **defensive, passive HTTP security analysis tool** that examines HTTP response headers (and, optionally, a bounded amount of response metadata/body) to identify **potentially sensitive or unsafe caching configurations**.

Built for security researchers, developers, QA engineers, and system administrators who need to understand whether responses containing potentially sensitive information might be cached by browsers, proxies, CDNs, or other shared caches.

> ⚠️ **Authorized use only.** This tool performs passive, read-only analysis (GET/HEAD requests, header/body inspection). It does **not** attempt exploitation, cache poisoning, cache deception attacks, authentication bypass, credential theft, brute forcing, or any other form of unauthorized access. **Only scan systems you own or are explicitly authorized to test.**

---

## Table of Contents

1. [Overview](#overview)
2. [Why Cache Configuration Matters](#why-cache-configuration-matters)
3. [Features](#features)
4. [Architecture](#architecture)
5. [Installation](#installation)
6. [CLI Usage](#cli-usage)
7. [Batch Usage](#batch-usage)
8. [Raw-Response / Headers / JSON Analysis](#raw-response--headers--json-analysis)
9. [Optional Web GUI](#optional-web-gui)
10. [Output Formats](#output-formats)
11. [Rule IDs](#rule-ids)
12. [Severity & Confidence Model](#severity--confidence-model)
13. [Example Findings](#example-findings)
14. [Remediation Guidance](#remediation-guidance)
15. [Testing](#testing)
16. [Troubleshooting](#troubleshooting)
17. [Security Considerations](#security-considerations)
18. [Authorized-Use Notice](#authorized-use-notice)
19. [Project Structure](#project-structure)
20. [License](#license)
21. [Creator & Support](#creator--support)

---

## Overview

HTTP caching is powerful, but a caching policy that is correct for a static marketing page can be **dangerous** for an authenticated dashboard, API response, or password-reset page. Cache-Control Analyzer helps you spot these mismatches *before* an attacker, auditor, or incident does.

The tool:

* Parses `Cache-Control` and related headers correctly (directives, parameters, quoting, duplicates, malformed values).
* Uses conservative, explainable heuristics to estimate whether a response is likely to contain sensitive/user-specific content.
* Runs a modular rule engine that cross-references caching policy with sensitivity, cookies, CDN headers, and authentication signals.
* Produces clear, professional reports (terminal, JSON, CSV, HTML, Markdown) with rule IDs, severity, confidence, evidence, and remediation guidance.

It **never** declares a finding "confirmed" based on a single signal (e.g. a bare `public` directive). Every finding is expressed as a likelihood with an explicit confidence level and rationale.

## Why Cache Configuration Matters

* **Shared caches (CDNs, reverse proxies, corporate proxies)** can store and later replay a response to a *different* user if the cache key doesn't properly account for identity.
* **`Cache-Control: public`** on a response containing personal data, session details, or internal identifiers can lead to **cross-user data exposure**.
* **Missing or weak `Cache-Control`** leaves caching behavior up to heuristics that vary across browsers, proxies, and CDNs.
* **CDN-specific headers** (`Surrogate-Control`, `CDN-Cache-Control`, `Cloudflare-CDN-Cache-Control`) can silently override standard `Cache-Control` behavior at the edge.
* **RFC 7234** places specific restrictions on caching authenticated (`Authorization`-bearing) requests that are easy to get wrong.

## Features

* **Correct Cache-Control parsing**: multiple directives, parameters (`max-age=600`), quoted values, duplicate directives, malformed/irregular input -- all handled without raising.
* **Sensitive-content heuristics**: URL-pattern, header, cookie, status-code, content-type, and (optional, capped) body-keyword signals combined into a LOW/MEDIUM/HIGH likelihood with a confidence level and full rationale. **Never claims certainty from URL patterns alone.**
* **Modular rule engine** (`cache_analyzer/rules/`) with stable, unique rule IDs (`CCA-###`), each producing a structured `Finding` (severity, confidence, evidence, affected headers, why-it-matters, remediation).
* **Cookie-aware analysis**: flags session/auth-like cookies on shared-cacheable responses without cache-key discrimination; checks `Secure`/`HttpOnly` in a caching context.
* **Authentication-aware heuristics**: implements the RFC 7234 rule that shared caches must not store responses to `Authorization`-bearing requests unless `public`, `must-revalidate`, or `s-maxage` is present.
* **CDN/proxy header analysis**: `Surrogate-Control`, `CDN-Cache-Control`, `Cloudflare-CDN-Cache-Control`.
* **Five analysis modes**: URL, raw HTTP response file, headers file, JSON file, and batch (multiple URLs).
* **Safe fetching**: GET/HEAD only, TLS verification by default, configurable timeout/redirects, recorded redirect chains, capped body size, retries with backoff.
* **Five output formats**: terminal (rich), JSON, CSV, HTML, Markdown.
* **Optional local web GUI** (Flask) with risk summary, findings list, and one-click export.
* **Structured logging** with automatic redaction of secrets (Authorization headers, cookies, tokens, passwords).
* **Concurrent batch mode** with configurable worker count and rate limiting.
* **Comprehensive automated test suite** (70+ tests) covering parsing, rules, scoring, fetching, and reporting.

## Architecture

```text
cache-control-analyzer/
│
├── main.py                     # CLI entry point
├── pyproject.toml
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
│
├── cache_analyzer/
│   ├── __init__.py              # Branding, version, banner
│   ├── cli.py                   # Typer CLI (analyze/batch/parse/rules/report/version/gui)
│   ├── config.py                 # AppConfig (timeouts, redirects, workers, ...)
│   ├── models.py                  # Pydantic models (HttpResponse, CachePolicy, Finding, ...)
│   ├── context.py                  # Shared AnalysisContext for rules
│   ├── analyzer.py                  # Orchestrates parsing -> scoring -> rules -> result
│   ├── fetcher.py                    # Safe HTTP fetching (httpx)
│   ├── parser.py                      # Cache-Control + input-mode parsing
│   ├── scoring.py                      # Sensitivity heuristics + risk aggregation
│   ├── reporter.py                      # Terminal/JSON/CSV/HTML/Markdown rendering
│   ├── logger.py                         # Structured, secret-redacting logging
│   ├── webgui.py                          # Optional local web GUI (Flask)
│   │
│   ├── rules/
│   │   ├── __init__.py            # run_all_rules() aggregator
│   │   ├── registry.py             # Static rule-ID metadata (for `rules` command)
│   │   ├── severity.py              # Shared remediation text / helpers
│   │   ├── cache_control.py          # Directive-level checks (CCA-010..019)
│   │   ├── sensitive_content.py        # Sensitivity x cache-policy (CCA-001..009)
│   │   ├── cdn.py                       # CDN/proxy header checks (CCA-020..029)
│   │   ├── cookies.py                    # Cookie-aware checks (CCA-030..039)
│   │   └── authentication.py              # Auth-aware checks (CCA-040..049)
│   │
│   └── utils/
│       ├── __init__.py
│       ├── validators.py           # URL validation, path-traversal-safe output paths
│       ├── http.py                  # Low-level header/cookie parsing helpers
│       └── formatting.py             # Human-readable sizes/times, HTML escaping
│
├── tests/
│   ├── test_parser.py
│   ├── test_cache_rules.py
│   ├── test_scoring.py
│   ├── test_fetcher.py
│   └── test_reporting.py
│
├── examples/                      # Sample fixtures (raw response, headers, JSON, URL list)
└── output/                         # Default destination for generated reports
```

## Installation

### Requirements

* Python 3.9+
* pip

### 1. Clone the repository

```bash
git clone <this-repository-url>
cd cache-control-analyzer
```

### 2. Create and activate a virtual environment

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Windows (cmd.exe):**

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

Or install as an editable package (enables the `cache-analyzer` command):

```bash
pip install -e .
```

For the optional web GUI:

```bash
pip install -e ".[gui]"
# or: pip install flask
```

### 4. (Optional) configure environment defaults

```bash
cp .env.example .env
# edit .env as needed
```

## CLI Usage

```bash
python main.py --help
python main.py analyze https://example.com/account
python main.py analyze https://example.com -o report.json --format json
python main.py analyze https://example.com --insecure --timeout 15 --no-follow-redirects
python main.py version
```

If installed via `pip install -e .`, you can use the `cache-analyzer` command instead of `python main.py`.

Key flags on `analyze` / `batch`:

| Flag | Description |
|---|---|
| `--timeout` | Request timeout in seconds (default 10) |
| `--user-agent` | Custom User-Agent header |
| `--follow-redirects` / `--no-follow-redirects` | Toggle redirect following |
| `--max-redirects` | Maximum redirects to follow (default 5) |
| `--format` / `-f` | `terminal`, `json`, `csv`, `html`, `markdown` |
| `--output` / `-o` | Write report to a file (path-traversal-safe; relative names go under `output/`) |
| `--verbose` / `-v` | Enable verbose logging |
| `--insecure` | Disable TLS certificate verification (**lab/testing only**) |
| `--no-body` | Skip fetching/analyzing the response body |

`analyze` exits non-zero when a target's overall risk is `HIGH` (exit code `3`), making it suitable for CI gating.

## Batch Usage

```bash
python main.py batch examples/urls.txt --format html -o report.html
python main.py batch examples/urls.txt --workers 8 --rate-limit 5 --retries 2
```

`urls.txt` contains one **authorized** URL per line; lines starting with `#` are ignored. Batch mode fetches concurrently (configurable `--workers`), rate-limits requests (`--rate-limit` requests/sec across all workers), retries transient network errors with backoff, and reports progress to stderr. Interrupting with Ctrl+C reports partial results gracefully.

## Raw-Response / Headers / JSON Analysis

Useful when you already captured a response (e.g. via your browser's dev tools or a proxy) and don't want to re-request it:

```bash
# Full raw HTTP response (status line + headers + optional body)
python main.py analyze --response examples/raw_response_sensitive.txt

# Just the headers (optionally prefixed by a status line)
python main.py analyze --headers examples/headers_safe.txt

# A JSON description of a response
python main.py analyze --json examples/response.json
```

JSON input schema (fields other than `url`/`headers` are optional):

```json
{
  "url": "https://example.com/account",
  "status_code": 200,
  "headers": { "Cache-Control": "public, max-age=600" },
  "body": "optional response body text",
  "redirect_chain": [{ "url": "https://example.com/", "status_code": 301 }]
}
```

## Optional Web GUI

A lightweight local web GUI is included for interactive use (no native desktop toolkit dependency, so it works the same on Windows/Linux/macOS and inside sandboxes):

```bash
pip install flask   # or: pip install -e ".[gui]"
python main.py gui --host 127.0.0.1 --port 8787
```

Then open `http://127.0.0.1:8787` in your browser. The GUI lets you:

* Enter a target URL **or** paste a raw response/headers block.
* Run an analysis (network fetches happen off the page-render path via background request handling, so the UI never freezes).
* View a HIGH/MEDIUM/LOW/INFO risk summary and the full findings list.
* Export the result as JSON, CSV, HTML, or Markdown.

The GUI's footer includes an About section with creator and support information.

## Output Formats

```bash
python main.py analyze https://example.com                      # terminal (default)
python main.py analyze https://example.com -f json -o out.json
python main.py analyze https://example.com -f csv  -o out.csv
python main.py analyze https://example.com -f html -o out.html
python main.py analyze https://example.com -f markdown -o out.md
```

You can also convert a previously saved JSON report into another format:

```bash
python main.py report output/out.json --format html -o out.html
```

## Rule IDs

Run `python main.py rules` to list every rule ID known to the engine. Summary:

| Range | Module | Focus |
|---|---|---|
| `CCA-001`..`CCA-009` | `sensitive_content.py` | Sensitivity x cache-policy interaction (core engine) |
| `CCA-010`..`CCA-019` | `cache_control.py` | Directive-level correctness (conflicts, malformed values) |
| `CCA-020`..`CCA-029` | `cdn.py` | CDN/proxy-specific caching headers |
| `CCA-030`..`CCA-039` | `cookies.py` | Cookie-aware caching risk |
| `CCA-040`..`CCA-049` | `authentication.py` | RFC 7234 Authorization-and-caching interaction |

## Severity & Confidence Model

**Severity** (overall risk is the highest severity among a target's findings):

* `HIGH` -- e.g. a response with strong sensitivity indicators is explicitly publicly cacheable, or an authenticated request's response explicitly permits shared caching.
* `MEDIUM` -- e.g. missing `Cache-Control` on a likely-sensitive response, long `max-age` without `private`, `s-maxage` on user-specific content, CDN headers alongside sensitivity indicators.
* `LOW` -- e.g. conflicting directives, cookies missing `Secure`/`HttpOnly` in a caching context, `private` directive present (reduces but doesn't eliminate risk).
* `INFORMATIONAL` -- e.g. `no-store` explicitly set, short-lived cache configuration, no sensitivity indicators detected, awareness-only CDN header usage.

**Confidence** (how sure the heuristics are, independent of severity): `HIGH`, `MEDIUM`, `LOW`. A `HIGH` severity finding with `MEDIUM` confidence should be read as *"if this response is sensitive, this is a serious issue -- but our confidence that it's sensitive is moderate."*

The tool deliberately avoids absolute language. You will not see "this is definitely vulnerable" -- instead: *"Potentially sensitive response appears cacheable by shared caches."*

## Example Findings

```text
[HIGH] CCA-001
Potentially sensitive response is publicly cacheable
Confidence : MEDIUM

Evidence:
  Cache-Control: public, max-age=600
  URL path suggests an account page
  Session/auth-like cookie(s) present: session_id

Recommendation:
  Review whether this endpoint is intended to be cached by shared/shared-aware
  infrastructure (CDNs, reverse proxies). If the content is user-specific,
  restrict caching to the browser only (private) or disable caching entirely
  (no-store), depending on sensitivity.
```

## Remediation Guidance

The right policy depends on the endpoint -- the tool does **not** universally recommend `no-store` for everything.

For highly sensitive responses (auth, payment, personal data):

```http
Cache-Control: no-store
```

For content only useful to the current browser session:

```http
Cache-Control: private, max-age=300
```

For genuinely public, non-user-specific content, `public` with an appropriate `max-age`/`s-maxage` may be entirely correct -- the tool will report this as informational/low rather than flag it.

## Testing

```bash
pip install -r requirements.txt
pytest -v
```

The suite (`tests/`) covers: Cache-Control parsing (duplicates, quoting, malformed values, all standard directives), the full rule engine (sensitive-content, cache-control, CDN, cookies, authentication rules), sensitivity scoring and risk aggregation, safe URL fetching (mocked, including redirects/timeouts/body truncation), and all four structured report formats (JSON/CSV/HTML/Markdown).

## Troubleshooting

* **`ModuleNotFoundError: No module named 'cache_analyzer'`** -- run commands from the repository root, or `pip install -e .`.
* **GUI fails to start with an ImportError** -- install the optional dependency: `pip install flask`.
* **TLS certificate errors against a lab target** -- use `--insecure` (lab/testing environments only; never use against production third-party systems).
* **Timeouts on slow targets** -- increase `--timeout`.
* **`analyze` exits with code 3** -- this indicates an overall `HIGH` risk result; useful for CI pipelines that should fail the build.
* **Report file written somewhere unexpected** -- output paths are sanitized against path traversal; plain filenames are written under `output/`.

## Security Considerations

* Passive analysis only: GET/HEAD requests, no forms submitted, no brute forcing, no cache poisoning/deception, no exploit traffic.
* TLS certificate validation is **on by default**; `--insecure` is opt-in and intended for lab/testing environments.
* Response bodies are capped (`--max-body-bytes` / `CCA_MAX_BODY_BYTES`, default 256 KB, hard ceiling 10 MB) to avoid unbounded memory use.
* Output file paths are sanitized to prevent path traversal; filenames are stripped of unsafe characters.
* Logging redacts `Authorization`, `Cookie`/`Set-Cookie`, API keys, tokens, and password-like values.
* Input file parsing never executes file content as code.

## Authorized-Use Notice

This tool performs **passive, read-only HTTP header analysis**. Only use it against systems you **own** or are **explicitly authorized** to test. Unauthorized scanning of third-party systems may be illegal in your jurisdiction and is outside the intended and supported use of this project.

## Project Structure

See [Architecture](#architecture) above for the full directory layout.

## License

Released under the [MIT License](LICENSE).

## Creator & Support

**Created by Mr Dinesh Pathro**

* Support: [https://buymeacoffee.com/mrdineshpathro](https://buymeacoffee.com/mrdineshpathro)
* YouTube: [https://youtube.com/@githubhacker?si=RhxMBWbdJx_VYDM3](https://youtube.com/@githubhacker?si=RhxMBWbdJx_VYDM3)

If this tool was useful for your security work, consider supporting its development via the link above.
