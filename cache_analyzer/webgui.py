"""
Optional lightweight GUI for Cache-Control Analyzer.

Implemented as a small local web application (rather than a native
desktop toolkit) so it works consistently across Windows/Linux/macOS
and inside containerized/sandboxed environments without a display
server. All network fetches run inside Flask's request-handling
threads (never blocking the page itself), and the browser UI performs
analysis via asynchronous requests so the interface stays responsive.

This GUI is OPTIONAL. The core tool is fully usable from the CLI
(`main.py` / `cache-analyzer`) without it. Requires the extra
`flask` dependency:

    pip install flask

Run with:

    python -m cache_analyzer.webgui
    # or
    python main.py gui
"""
from __future__ import annotations

import io
from typing import Optional

from cache_analyzer import __author__, __support_url__, __title__, __version__, __youtube_url__, AUTHORIZED_USE_NOTICE
from cache_analyzer.analyzer import analyze_response
from cache_analyzer.config import AppConfig
from cache_analyzer.fetcher import FetchError, fetch_from_config
from cache_analyzer.models import Report, ScanMetadata
from cache_analyzer.parser import parse_cache_control
from cache_analyzer.reporter import render_csv, render_html, render_json, render_markdown
from cache_analyzer.utils.validators import ValidationError, is_private_host, validate_url

try:
    from flask import Flask, jsonify, request, Response
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "The optional web GUI requires Flask. Install it with: pip install flask"
    ) from exc


def create_app() -> "Flask":
    app = Flask(__name__)

    @app.get("/")
    def index() -> str:
        return _INDEX_HTML

    @app.post("/api/analyze")
    def api_analyze():
        payload = request.get_json(force=True, silent=True) or {}
        mode = payload.get("mode", "url")

        try:
            if mode == "url":
                url = (payload.get("url") or "").strip()
                validate_url(url)
                config = AppConfig(
                    timeout_seconds=float(payload.get("timeout", 10.0)),
                    insecure=bool(payload.get("insecure", False)),
                ).clamp()
                http_response = fetch_from_config(url, config)
                metadata = ScanMetadata(mode="url", timeout_seconds=config.timeout_seconds)
                warning = "This host looks private/loopback -- ensure you are authorized." if is_private_host(url) else None
            elif mode == "headers":
                from cache_analyzer.utils.http import parse_raw_headers

                raw_text = payload.get("raw_text", "")
                headers = parse_raw_headers(raw_text.splitlines())
                from cache_analyzer.parser import response_from_headers_dict

                http_response = response_from_headers_dict(
                    payload.get("url") or "local://gui-input", headers, source="headers_file"
                )
                metadata = ScanMetadata(mode="headers_file")
                warning = None
            else:
                return jsonify({"error": f"Unsupported mode '{mode}'"}), 400

            result = analyze_response(http_response, metadata=metadata)
        except (ValidationError, FetchError) as exc:
            return jsonify({"error": str(exc)}), 400

        report = Report(results=[result])
        data = jsonify_report_summary(report)
        if warning:
            data["warning"] = warning
        # Stash full JSON for export endpoints.
        data["_report_json"] = report.model_dump(mode="json")
        return jsonify(data)

    @app.post("/api/export/<fmt>")
    def api_export(fmt: str):
        payload = request.get_json(force=True, silent=True) or {}
        report_dict = payload.get("report")
        if not report_dict:
            return jsonify({"error": "Missing report payload"}), 400
        report = Report.model_validate(report_dict)

        try:
            if fmt == "json":
                content, mimetype = render_json(report), "application/json"
            elif fmt == "csv":
                content, mimetype = render_csv(report), "text/csv"
            elif fmt == "html":
                content, mimetype = render_html(report), "text/html"
            elif fmt in ("markdown", "md"):
                content, mimetype = render_markdown(report), "text/markdown"
            else:
                return jsonify({"error": f"Unsupported format '{fmt}'"}), 400
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": str(exc)}), 500

        return Response(
            content,
            mimetype=mimetype,
            headers={"Content-Disposition": f"attachment; filename=cache-analyzer-report.{fmt}"},
        )

    @app.get("/api/parse")
    def api_parse():
        value = request.args.get("value", "")
        directives = parse_cache_control(value)
        return jsonify({"directives": directives})

    @app.get("/api/about")
    def api_about():
        return jsonify(
            {
                "tool": __title__,
                "version": __version__,
                "author": __author__,
                "support_url": __support_url__,
                "youtube_url": __youtube_url__,
                "notice": AUTHORIZED_USE_NOTICE,
            }
        )

    return app


def jsonify_report_summary(report: Report) -> dict:
    counts = report.counts_by_severity()
    result = report.results[0]
    return {
        "target": result.target,
        "status_code": result.response.status_code,
        "content_type": result.response.content_type,
        "risk_level": result.risk_level.value,
        "counts": counts,
        "cache_control": result.cache_policy.raw_cache_control,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "affected_headers": f.affected_headers,
                "recommendation": f.recommendation,
            }
            for f in result.findings
        ],
    }


_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cache-Control Analyzer</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#0f1115; color:#e6e6e6; margin:0; }
  header { background:#161920; padding:1rem 2rem; border-bottom:1px solid #2a2f3a; }
  header h1 { margin:0; font-size:1.3rem; color:#5dade2; }
  main { max-width: 900px; margin: 2rem auto; padding: 0 1rem; }
  .notice { background:#3b2f0b; border:1px solid #6b5416; padding:0.75rem 1rem; border-radius:6px; margin-bottom:1.5rem; font-size:0.9rem; }
  .panel { background:#1b1e26; border-radius:8px; padding:1.25rem 1.5rem; margin-bottom:1.5rem; }
  input[type=text], textarea { width:100%; box-sizing:border-box; padding:0.5rem; border-radius:4px; border:1px solid #333; background:#10131a; color:#e6e6e6; }
  textarea { min-height:120px; font-family: monospace; }
  button { background:#2980b9; color:white; border:none; padding:0.5rem 1rem; border-radius:4px; cursor:pointer; margin-right:0.5rem; margin-top:0.5rem; }
  button.secondary { background:#444; }
  button:hover { opacity:0.9; }
  .tabs { display:flex; gap:0.5rem; margin-bottom:1rem; }
  .tab { padding:0.4rem 0.8rem; border-radius:4px; cursor:pointer; background:#262b36; }
  .tab.active { background:#2980b9; }
  .risk { display:inline-block; padding:0.2rem 0.8rem; border-radius:999px; font-weight:bold; }
  .risk-HIGH { background:#c0392b; }
  .risk-MEDIUM { background:#d68910; }
  .risk-LOW { background:#2980b9; }
  .risk-INFORMATIONAL { background:#7f8c8d; }
  .finding { border-left:4px solid #555; background:#20242e; padding:0.75rem 1rem; margin:0.75rem 0; border-radius:4px; }
  .summary-grid { display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1rem; }
  .card { background:#10131a; border-radius:6px; padding:0.75rem 1.25rem; min-width:100px; }
  .card h4 { margin:0; font-size:0.75rem; color:#9aa5b1; text-transform:uppercase; }
  .card p { margin:0.25rem 0 0; font-size:1.4rem; font-weight:bold; }
  footer { text-align:center; color:#9aa5b1; font-size:0.85rem; padding:2rem 0; }
  a { color:#5dade2; }
  pre { white-space:pre-wrap; background:#10131a; padding:0.5rem; border-radius:4px; }
</style>
</head>
<body>
<header><h1>CACHE-CONTROL ANALYZER</h1></header>
<main>
  <div class="notice" id="notice">Loading authorized-use notice...</div>

  <div class="panel">
    <div class="tabs">
      <div class="tab active" data-mode="url">Target URL</div>
      <div class="tab" data-mode="headers">Import Response</div>
    </div>

    <div id="url-mode">
      <input type="text" id="url-input" placeholder="https://example.com/account">
    </div>
    <div id="headers-mode" style="display:none;">
      <textarea id="headers-input" placeholder="HTTP/1.1 200 OK&#10;Cache-Control: public, max-age=600&#10;Set-Cookie: session=abc; HttpOnly"></textarea>
    </div>

    <button onclick="analyze()">Analyze</button>
    <button class="secondary" onclick="clearAll()">Clear</button>
  </div>

  <div class="panel" id="results" style="display:none;">
    <h2>Risk Summary</h2>
    <p>Target: <span id="r-target"></span> &nbsp; Risk: <span id="r-risk" class="risk"></span></p>
    <div class="summary-grid">
      <div class="card"><h4>High</h4><p id="c-HIGH">0</p></div>
      <div class="card"><h4>Medium</h4><p id="c-MEDIUM">0</p></div>
      <div class="card"><h4>Low</h4><p id="c-LOW">0</p></div>
      <div class="card"><h4>Info</h4><p id="c-INFORMATIONAL">0</p></div>
    </div>

    <h2>Findings</h2>
    <div id="findings"></div>

    <h2>Export</h2>
    <button onclick="exportReport('json')">Export JSON</button>
    <button onclick="exportReport('csv')">Export CSV</button>
    <button onclick="exportReport('html')">Export HTML</button>
    <button onclick="exportReport('markdown')">Export Markdown</button>
  </div>

  <footer id="about">Loading...</footer>
</main>

<script>
let currentMode = 'url';
let lastReport = null;

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    currentMode = tab.dataset.mode;
    document.getElementById('url-mode').style.display = currentMode === 'url' ? 'block' : 'none';
    document.getElementById('headers-mode').style.display = currentMode === 'headers' ? 'block' : 'none';
  });
});

async function loadAbout() {
  const res = await fetch('/api/about');
  const data = await res.json();
  document.getElementById('notice').innerText = data.notice;
  document.getElementById('about').innerHTML =
    `Created by ${data.author}<br>Support: <a href="${data.support_url}">${data.support_url}</a> &nbsp;|&nbsp; YouTube: <a href="${data.youtube_url}">${data.youtube_url}</a>`;
}
loadAbout();

async function analyze() {
  const body = currentMode === 'url'
    ? { mode: 'url', url: document.getElementById('url-input').value }
    : { mode: 'headers', raw_text: document.getElementById('headers-input').value };

  const res = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) { alert('Error: ' + data.error); return; }

  lastReport = data._report_json;
  document.getElementById('results').style.display = 'block';
  document.getElementById('r-target').innerText = data.target;
  const riskEl = document.getElementById('r-risk');
  riskEl.innerText = data.risk_level;
  riskEl.className = 'risk risk-' + data.risk_level;

  for (const sev of ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']) {
    document.getElementById('c-' + sev).innerText = data.counts[sev] || 0;
  }

  const findingsEl = document.getElementById('findings');
  findingsEl.innerHTML = '';
  for (const f of data.findings) {
    const div = document.createElement('div');
    div.className = 'finding';
    div.innerHTML = `<strong>${f.rule_id}</strong> [${f.severity}] &mdash; ${f.title}<br>
      <em>Confidence: ${f.confidence}</em>
      <pre>${f.evidence.join('\\n')}</pre>
      <p>${f.recommendation}</p>`;
    findingsEl.appendChild(div);
  }
}

function clearAll() {
  document.getElementById('url-input').value = '';
  document.getElementById('headers-input').value = '';
  document.getElementById('results').style.display = 'none';
}

async function exportReport(fmt) {
  if (!lastReport) { alert('Run an analysis first.'); return; }
  const res = await fetch('/api/export/' + fmt, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ report: lastReport }),
  });
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'cache-analyzer-report.' + fmt;
  a.click();
}
</script>
</body>
</html>
"""


def main(host: str = "0.0.0.0", port: int = 8787, debug: bool = False) -> None:
    app = create_app()
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
