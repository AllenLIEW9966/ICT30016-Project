from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from app.scanner.python_scanner import scan
from app.scanner import js_scanner
from app.scanner.dependency_scanner import scan as scan_dependencies
from app.scanner.dependency_scanner import advisory_findings

router = APIRouter()


class AdvisoryRequest(BaseModel):
    code: str = Field(max_length=512_000)
    filename: str = Field(max_length=512)
    lock_text: str = Field(default="", max_length=2_097_152)


@router.post("/dependency-advisories")
async def dependency_advisories(req: AdvisoryRequest):
    return {"findings": await advisory_findings(req.code, req.filename, req.lock_text)}


class ScanRequest(BaseModel):
    require_ast: bool = False
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

    if req.require_ast:
        if language == "python":
            import ast
            try:
                tree = await run_in_threadpool(ast.parse, code, filename=req.filename)
                await run_in_threadpool(compile, tree, req.filename, "exec")
            except SyntaxError as exc:
                return {"ast_validated": True, "findings": [{"rule_id": "PARSE-ERROR", "message": f"{exc.msg} at line {exc.lineno}"}]}
        elif language in {"javascript", "js"}:
            from app.scanner.js_ast_bridge import scan_with_ast
            parsed = await run_in_threadpool(scan_with_ast, code, req.filename, True)
            if parsed is None:
                raise HTTPException(status_code=503, detail="AST parser unavailable; AI patch validation blocked")
            if any(f.get("rule_id") == "PARSE-ERROR" for f in parsed):
                return {"ast_validated": True, "findings": parsed}
        else:
            raise HTTPException(status_code=400, detail="AI patch syntax validation requires Python or JavaScript")

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
        "ast_validated": req.require_ast,
        "language": language,
        "filename": req.filename,
        "findings_count": len(findings),
        "findings": findings,
        "scan_time_ms": round(elapsed_ms, 2),
    }
