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
    allow_origins=["*"],
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
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
