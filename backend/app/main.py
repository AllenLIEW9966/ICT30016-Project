from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

from app.routes.scan import router as scan_router
from app.routes.suggest import router as suggest_router
from app.routes.health import router as health_router

app = FastAPI(
    title="Secure Coding Assistant API",
    description="Static analysis + AI-powered secure coding suggestions.",
    version="0.1.51",
)


class RequestSizeLimitMiddleware:
    """Reject oversized bodies before JSON validation allocates/parses them."""

    def __init__(self, app, max_body_bytes: int = 1_048_576):
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        declared_length = headers.get(b"content-length")
        if declared_length:
            try:
                if int(declared_length) > self.max_body_bytes:
                    await self._too_large(scope, receive, send)
                    return
            except ValueError:
                await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(scope, receive, send)
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.max_body_bytes:
                await self._too_large(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay_body():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_body, send)

    async def _too_large(self, scope, receive, send):
        response = JSONResponse({"detail": "Request body exceeds the 1 MB limit"}, status_code=413)
        await response(scope, receive, send)


app.add_middleware(RequestSizeLimitMiddleware)


@app.exception_handler(RequestValidationError)
async def sanitized_validation_error(_request: Request, exc: RequestValidationError):
    # Pydantic's default response includes rejected input values, which may
    # contain source code or credentials. Return locations and error types only.
    errors = [
        {"loc": list(error.get("loc", ())), "type": error.get("type", "value_error"), "msg": error.get("msg", "Invalid value")}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})

app.add_middleware(
    CORSMiddleware,
    # C7: restrict CORS to loopback origins only — never wildcard in production.
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
)

app.include_router(health_router)
app.include_router(scan_router)
app.include_router(suggest_router)


@app.get("/")
async def root():
    return {"status": "ok", "service": "secure-coding-assistant"}


if __name__ == "__main__":
    import sys
    import uvicorn
    host, port = "127.0.0.1", 8000
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--host" and i + 1 < len(args):
            host = args[i + 1]
        if a == "--port" and i + 1 < len(args):
            try:
                port = int(args[i + 1])
            except ValueError:
                pass
    # A1/C7: frozen exe binds loopback only; never 0.0.0.0 from the manager.
    if host not in ("127.0.0.1", "localhost", "::1"):
        host = "127.0.0.1"
    uvicorn.run("app.main:app", host=host, port=port, reload=False)
