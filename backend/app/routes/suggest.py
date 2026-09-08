from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()


class SuggestionRequest(BaseModel):
    rule_id: str
    title: str
    severity: str
    cwe_id: str
    owasp_ref: str
    language: str
    code_snippet: str
    context: dict = Field(default_factory=dict)


class SuggestionResponse(BaseModel):
    explanation: str
    secure_code: str
    references: list[str] = []


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
            language=req.language,
            code_snippet=req.code_snippet,
            context=req.context,
        )
        return SuggestionResponse(**result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
