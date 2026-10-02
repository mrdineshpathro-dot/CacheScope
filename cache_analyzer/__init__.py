"""
Cache-Control Analyzer
=======================

A defensive HTTP security analysis tool that inspects HTTP response
headers (and, optionally, limited response metadata) to identify
potentially sensitive or unsafe caching configurations.

This tool performs PASSIVE ANALYSIS ONLY. It does not attempt
exploitation, cache poisoning, cache-deception attacks, authentication
bypass, credential theft, or any other form of unauthorized access.

Only use this tool against systems you own or are explicitly
authorized to test.

Created by Mr Dinesh Pathro
Support : https://buymeacoffee.com/mrdineshpathro
YouTube : https://youtube.com/@githubhacker?si=RhxMBWbdJx_VYDM3
"""

__title__ = "Cache-Control Analyzer"
__slug__ = "cache-control-analyzer"
__version__ = "1.0.0"
__author__ = "Mr Dinesh Pathro"
__support_url__ = "https://buymeacoffee.com/mrdineshpathro"
__youtube_url__ = "https://youtube.com/@githubhacker?si=RhxMBWbdJx_VYDM3"
__license__ = "MIT"

BANNER = r"""
╭──────────────────────────────────────────────╮
│           CACHE-CONTROL ANALYZER             │
╰──────────────────────────────────────────────╯
"""

AUTHORIZED_USE_NOTICE = (
    "This tool performs passive, read-only HTTP header analysis. "
    "Only scan systems that you own or are explicitly authorized to test. "
    "Unauthorized scanning of third-party systems may be illegal."
)

FOOTER_TEXT = (
    "Created by Mr Dinesh Pathro\n"
    "Support: buymeacoffee.com/mrdineshpathro\n"
    "YouTube: @githubhacker"
)
