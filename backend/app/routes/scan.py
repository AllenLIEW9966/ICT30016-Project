from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.scanner.python_scanner import scan
from app.scanner import js_scanner

router = APIRouter()


class ScanRequest(BaseModel):
    language: str = Field(..., description="'python' or 'javascript'")
    code: str = Field(..., description="Source code to scan")
    filename: str = Field("untitled", description="File name for context")


@router.post("/scan")
async def scan_code(req: ScanRequest):
    language = req.language.lower()
    code = req.code

    if language == "python":
        findings = scan(code, filename=req.filename)
    elif language in ("javascript", "js"):
        findings = js_scanner.scan(code, filename=req.filename)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported language: {language}")

    return {
        "language": language,
        "filename": req.filename,
        "findings_count": len(findings),
        "findings": findings,
    }
