"""O-02 context bounding + prompt harness.

extract_context(): bounded window around the finding line, capped so
local 7B quantized models stay in context and under NFR-01 latency.
"""
from __future__ import annotations

import re

MAX_CONTEXT_LINES = 40
MAX_SNIPPET_CHARS = 2000

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b[A-Z0-9_.-]*(?:PASSWORD|PASSWD|SECRET|API[_-]?KEY|TOKEN|CREDENTIAL|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)[A-Z0-9_.-]*\b\s*[:=]\s*)"
    r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|`[^`\r\n]*`|[^\s,;#]+)"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
_URL_CREDENTIALS = re.compile(r"(https?://)[^/@\s:]+:[^/@\s]+@", re.IGNORECASE)
_SAFE_SECRET_REFERENCES = re.compile(r"^(?:os\.environ|process\.env|env\[|secrets\.|getenv\(|none\b|null\b|undefined\b)", re.IGNORECASE)


def redact_sensitive_text(text: str) -> str:
    """Mask common credential assignments and key blocks before building AI prompts."""
    redacted = _PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY]", text)
    redacted = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", redacted)
    def replace_assignment(match: re.Match[str]) -> str:
        prefix, value = match.groups()
        unwrapped = value.strip("\"'`")
        if _SAFE_SECRET_REFERENCES.match(unwrapped):
            return match.group(0)
        if len(value) >= 2 and value[0] in "\"'`" and value[-1] == value[0]:
            return prefix + value[0] + "[REDACTED]" + value[0]
        return prefix + "[REDACTED]"

    return _SECRET_ASSIGNMENT.sub(replace_assignment, redacted)


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
