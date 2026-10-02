#!/usr/bin/env python3
"""
Cache-Control Analyzer -- entry point.

Usage:
    python main.py analyze https://example.com/account
    python main.py analyze --response response.txt
    python main.py analyze --headers headers.txt
    python main.py analyze --json response.json
    python main.py batch urls.txt
    python main.py rules
    python main.py version

Created by Mr Dinesh Pathro
Support : https://buymeacoffee.com/mrdineshpathro
YouTube : https://youtube.com/@githubhacker?si=RhxMBWbdJx_VYDM3

IMPORTANT: Only scan systems you own or are explicitly authorized to
test. This tool performs passive, read-only HTTP header analysis and
must never be used for exploitation, cache poisoning, cache-deception
attacks, or unauthorized access.
"""
from cache_analyzer.cli import app

if __name__ == "__main__":
    app()
