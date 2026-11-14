import asyncio
import json
from unittest.mock import AsyncMock, patch

from app.ai.ai_client import suggest_fix
from app.ai.context import extract_context


def test_ai_prompt_context_window():
    source = "\n".join(f"value_{i} = {i}" for i in range(1, 101))
    lines = source.splitlines()
    lines[49] = 'message = "' + "x" * 2500 + '"'
    source = "\n".join(lines)
    assert extract_context(source, 1)["end_line"] == 21
    assert extract_context(source, 100)["start_line"] == 80
    assert len(extract_context(source, 50)["snippet"].splitlines()) == 41

    async def exercise():
        response = json.dumps({"can_fix": False, "explanation": "test", "secure_code": "", "references": []})
        for provider in ("ollama", "groq", "gemini", "openrouter"):
            # Exercise both new window payloads and legacy full-source clients.
            for payload in ({"source_window": "\n".join(lines[29:70]),
                             "source_start_line": 30, "source_total_lines": 100},
                            {"full_source": source}):
                call = AsyncMock(return_value=response)
                target = "_call_ollama" if provider == "ollama" else "_call_openai_compatible"
                with patch("app.ai.ai_client." + target, call):
                    await suggest_fix(rule_id="PY-LOG-001", title="test", severity="high",
                                      cwe_id="CWE-532", owasp_ref="A09:2025", language="python",
                                      code_snippet="message", context={**payload, "line": 50,
                                      "end_line": 90, "ai_provider": provider, "ai_api_key": "synthetic"})
                prompt = call.call_args.args[-1]
                assert "context lines 30-70 of 100" in prompt
                assert "30: value_30 = 30" in prompt and "70: value_70 = 70" in prompt
                assert "value_29" not in prompt and "value_71" not in prompt
                assert "x" * 2500 in prompt  # No arbitrary character cutoff.
                assert "current_file_module_header" not in prompt
    asyncio.run(exercise())
