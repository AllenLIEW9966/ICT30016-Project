from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.scan import router as scan_router
from app.routes.suggest import router as suggest_router
from app.routes.health import router as health_router

app = FastAPI(
    title="Secure Coding Assistant API",
    description="Static analysis + AI-powered secure coding suggestions.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    # C7: restrict CORS to loopback origins only — never wildcard in production.
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["*"],
    allow_headers=["*"],
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
