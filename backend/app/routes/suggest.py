import json
import logging
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

router = APIRouter()
logger = logging.getLogger(__name__)


class SuggestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., min_length=1, max_length=64)
    title: str = Field(..., min_length=1, max_length=256)
    severity: str = Field(..., min_length=1, max_length=32)
    cwe_id: str = Field(..., max_length=64)
    owasp_ref: str = Field(..., max_length=128)
    owasp_2021_ref: str = Field("N/A", max_length=128)
    language: str = Field(..., min_length=1, max_length=32)
    code_snippet: str = Field(..., max_length=4_000)
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("context")
    @classmethod
    def bound_context(cls, value: dict[str, Any]) -> dict[str, Any]:
        # The extension bounds and redacts project context too; this server-side
        # limit protects the endpoint if another client bypasses that UI.
        try:
            encoded = json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("context must contain JSON-compatible values") from exc
        if len(encoded) > 128_000:
            raise ValueError("context exceeds the 128 KB limit")
        full_source = value.get("full_source", "")
        if not isinstance(full_source, str) or len(full_source) > 512_000:
            raise ValueError("full_source must be text no larger than 512 KB")
        related = value.get("related_project_files", [])
        if not isinstance(related, list) or len(related) > 8:
            raise ValueError("related_project_files must contain at most 8 files")
        if any(
            not isinstance(item, dict)
            or not isinstance(item.get("path", ""), str)
            or len(item.get("path", "")) > 512
            or not isinstance(item.get("content", ""), str)
            or len(item.get("content", "")) > 6_000
            for item in related
        ):
            raise ValueError("related project file entries exceed the supported limits")
        return value


class SuggestionResponse(BaseModel):
    can_fix: bool = True
    explanation: str
    secure_code: str
    references: list[str] = Field(default_factory=list)
    source: str = "provider"
    provider: str = "ollama"
    warning: str | None = None


@router.post("/suggest-fix", response_model=SuggestionResponse)
async def suggest_fix_endpoint(req: SuggestionRequest):
    from app.ai.ai_client import suggest_fix
    try:
        result = await suggest_fix(
            rule_id=req.rule_id,
            title=req.title,
            severity=req.severity,
            cwe_id=req.cwe_id,
            owasp_ref=req.owasp_ref,
            owasp_2021_ref=req.owasp_2021_ref,
            language=req.language,
            code_snippet=req.code_snippet,
            context=req.context,
        )
        return SuggestionResponse(**result)
    except httpx.TimeoutException:
        logger.warning("AI provider request timed out (provider=%s, model=%s)", req.context.get("ai_provider", "ollama"), req.context.get("ai_model", ""))
        raise HTTPException(status_code=504, detail="The AI provider timed out. Check the model service and try again.") from None
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        logger.warning("AI provider returned HTTP %d (provider=%s)", status, req.context.get("ai_provider", "ollama"))
        raise HTTPException(status_code=502, detail="The AI provider rejected or could not complete the request. Check provider credentials, model ID, quota, and provider status.") from None
    except (httpx.RequestError, ValueError) as exc:
        # Do not echo exception text; provider/network exceptions can contain
        # endpoint details and user configuration.
        logger.warning("AI fix request could not be completed (%s)", type(exc).__name__)
        raise HTTPException(status_code=502, detail="Could not complete the AI fix request. Check provider configuration and connectivity.") from None
    except Exception:
        logger.exception("Unexpected error while preparing AI fix")
        raise HTTPException(status_code=500, detail="The server could not prepare this AI fix. See the backend log for details.") from None
