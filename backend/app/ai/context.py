"""O-02 context bounding + prompt harness.

extract_context(): bounded window around the finding line, capped so
local 7B quantized models stay in context and under NFR-01 latency.
"""
from __future__ import annotations

MAX_CONTEXT_LINES = 40
MAX_SNIPPET_CHARS = 2000


def extract_context(
    source: str,
    line: int,
    end_line: int | None = None,
    window: int = 15,
) -> dict:
    lines = source.splitlines()
    total = len(lines)
    end = end_line or line
    start = max(1, line - window)
    stop = min(total, end + window)
    snippet = "\n".join(lines[start - 1 : stop])
    if len(snippet) > MAX_SNIPPET_CHARS:
        snippet = snippet[:MAX_SNIPPET_CHARS] + "\n# ... (truncated)"
    return {
        "start_line": start,
        "end_line": stop,
        "total_lines": total,
        "snippet": snippet,
    }
