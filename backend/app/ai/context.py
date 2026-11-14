"""O-02 context bounding + prompt harness.

extract_context(): complete lines around the finding, without cutting code
mid-line. The default window includes 20 lines on each side.
"""
from __future__ import annotations

import re

MAX_CONTEXT_LINES = 41

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
    window: int = 20,
) -> dict:
    lines = source.splitlines()
    total = len(lines)
    line = max(1, min(total or 1, line))
    start = max(1, line - window)
    stop = min(total, line + window)
    snippet = "\n".join(lines[start - 1 : stop])
    return {
        "start_line": start,
        "end_line": stop,
        "total_lines": total,
        "snippet": snippet,
    }


def extract_module_header(source: str, language: str, max_chars: int = 3000) -> str:
    """Return bounded imports and top-level bindings from the target module.

    A finding-centered window can omit imports near the file's beginning. This
    compact view gives AI fixes the target module's actual available names,
    without sending a second copy of the whole source file.
    """
    lines = source.splitlines()
    selected: list[str] = []
    total_chars = 0
    python = language.lower() == "python"
    import_pattern = re.compile(
        r"^\s*(?:import\s+|from\s+\S+\s+import\b)" if python
        else r"^\s*(?:import\s+|(?:const|let|var)\s+\w+\s*=\s*require\s*\()"
    )
    binding_pattern = re.compile(
        r"^[A-Za-z_]\w*\s*=" if python
        else r"^(?:(?:export\s+)?(?:const|let|var)\s+)[A-Za-z_$][\w$]*\s*="
    )
    for line in lines:
        if not (import_pattern.search(line) or binding_pattern.search(line)):
            continue
        if len(line) > 500:
            line = line[:500] + " … [line truncated]"
        if total_chars + len(line) + 1 > max_chars:
            break
        selected.append(line)
        total_chars += len(line) + 1
        if len(selected) >= 60:
            break
    return "\n".join(selected)
