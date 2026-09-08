"""Scanner package."""

from app.scanner.python_scanner import scan
from app.scanner import js_scanner

__all__ = ["scan", "js_scanner"]
