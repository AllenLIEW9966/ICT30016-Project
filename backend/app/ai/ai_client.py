"""
AI client: builds prompts and calls an OpenAI-compatible API.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

PROMPT_TEMPLATE = """\
You are a security coding assistant. Fix the {language} code below.

Vulnerability: {title} (OWASP {owasp_ref}, {cwe_id}, severity {severity})
Rule: {rule_id}
Finding at line {line} (context lines {ctx_start}-{ctx_end} of {total}):

```{language}
{snippet}
```

RULES:
- Return ONLY valid JSON with keys: explanation, secure_code, references.
- explanation: 1-2 sentences on the flaw and the fix.
- secure_code: minimal replacement for the vulnerable lines only.
  Use parameterized queries for SQLi, env vars for secrets,
  allowlist + abspath checks for paths, verify() for JWT.
- Do NOT invent imports beyond the file's existing ones unless required.
- references: list of OWASP/CWE URLs (may be empty).
"""


async def suggest_fix(
    *,
    rule_id: str,
    title: str,
    severity: str,
    cwe_id: str,
    owasp_ref: str,
    language: str,
    code_snippet: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    # O-02: bounded context — prefer full-source window over bare snippet
    from app.ai.context import extract_context

    line = int(context.get("line", 1) or 1)
    end_line = context.get("end_line", line)
    full_source = context.get("full_source", "")
    if full_source:
        ctx = extract_context(str(full_source), line, int(end_line or line))
        snippet = ctx["snippet"]
        ctx_start, ctx_end, total = ctx["start_line"], ctx["end_line"], ctx["total_lines"]
    else:
        snippet = code_snippet[:2000]
        ctx_start, ctx_end, total = line, int(end_line or line), line

    prompt = PROMPT_TEMPLATE.format(
        language=language,
        title=title,
        owasp_ref=owasp_ref,
        cwe_id=cwe_id,
        severity=severity,
        rule_id=rule_id,
        line=line,
        ctx_start=ctx_start,
        ctx_end=ctx_end,
        total=total,
        snippet=snippet,
    )

    api_base = context.get("ai_api_base", "http://localhost:11434/v1")
    api_key = context.get("ai_api_key", "ollama")
    model = context.get("ai_model", "codellama:7b-instruct")

    # O-02 fallback: deterministic patch when the local LLM is unreachable
    def _fallback() -> dict[str, Any] | None:
        try:
            from app.ai.templates import template_fix
            return template_fix(language, rule_id)
        except Exception:
            return None

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Return only valid JSON."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }

    try:
        async with httpx.AsyncClient(timeout=180) as client:
            response = await client.post(
                f"{api_base}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
    except Exception:
        fb = _fallback()
        if fb is not None:
            return fb
        raise

    try:
        return json.loads(content.strip())
    except json.JSONDecodeError:
        # Fallback: extract secure code from markdown code block and explanation from text
        import re
        code_match = re.search(r"```(?:\w+)?\s*\n(.*?)\n```", content, re.DOTALL)
        secure_code = code_match.group(1).strip() if code_match else ""
        # Remove code block and references to get plain explanation
        explanation = re.sub(r"```.*?```", "", content, flags=re.DOTALL).strip()
        explanation = re.sub(r"\*.*?\*", "", explanation).strip()
        # Extract links from markdown
        refs = re.findall(r"<([^>]+)>", content)
        return {
            "explanation": explanation or "AI response could not be parsed.",
            "secure_code": secure_code,
            "references": refs,
        }
