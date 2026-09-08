"""
AI client: builds prompts and calls an OpenAI-compatible API.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

PROMPT_TEMPLATE = """\
You are a security coding assistant. The following {language} code contains a \
{vulnerability_type} vulnerability (OWASP Top 10: {owasp_ref}, CWE-{cwe_id}).

Vulnerability: {title}
Severity: {severity}

Vulnerable code:
```{language}
{code_snippet}
```

Explain the vulnerability in 1-2 sentences, then provide a secure alternative.
Return ONLY valid JSON with keys: explanation, secure_code, references (list of URLs).
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
    prompt = PROMPT_TEMPLATE.format(
        language=language,
        vulnerability_type=title,
        owasp_ref=owasp_ref,
        cwe_id=cwe_id,
        title=title,
        severity=severity,
        code_snippet=code_snippet,
    )

    api_base = context.get("ai_api_base", "http://localhost:8001/v1")
    api_key = context.get("ai_api_key", "not-set")
    model = context.get("ai_model", "gpt-4o-mini")

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Return only valid JSON."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }

    async with httpx.AsyncClient(timeout=180) as client:
        response = await client.post(
            f"{api_base}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json=payload,
        )
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"]

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
