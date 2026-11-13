from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from app.scanner.python_scanner import scan
from app.scanner import js_scanner
from app.scanner.dependency_scanner import scan as scan_dependencies

router = APIRouter()


class ScanRequest(BaseModel):
    language: str = Field(..., min_length=1, max_length=32, description="'python', 'javascript', or 'dependencies'")
    code: str = Field(..., max_length=512_000, description="Source code to scan (maximum 512 KB)")
    filename: str = Field("untitled", max_length=512, description="File name for context")


@router.post("/scan")
async def scan_code(req: ScanRequest):
    import time
    language = req.language.lower()
    code = req.code
    t0 = time.perf_counter()

    if language not in {"python", "javascript", "js", "dependencies"}:
        raise HTTPException(status_code=400, detail=f"Unsupported language: {language}")

    # Scanning is synchronous CPU work; keep it off FastAPI's event loop so one
    # large workspace file does not stall health checks or other requests.
    if language == "python":
        findings = await run_in_threadpool(scan, code, filename=req.filename)
    elif language in ("javascript", "js"):
        findings = await run_in_threadpool(js_scanner.scan, code, filename=req.filename)
    else:
        findings = await run_in_threadpool(scan_dependencies, code, filename=req.filename)

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "language": language,
        "filename": req.filename,
        "findings_count": len(findings),
        "findings": findings,
        "scan_time_ms": round(elapsed_ms, 2),
    }
