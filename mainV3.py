"""Compatibility layer preserving the old entry points.

The original project bundled UI, database and network logic into a single
`mainV3.py` file.  For testability and maintainability this module now
re-exports the refactored components located in dedicated packages.
"""

from ui import WebsiteVerificationTool
from scanner import fetch_rdap, parse_registrar_from_rdap

__all__ = [
    "WebsiteVerificationTool",
    "fetch_rdap",
    "parse_registrar_from_rdap",
]
