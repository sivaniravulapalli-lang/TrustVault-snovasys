from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import auth
from .db import engine
from .models import Base
from .routes import admin, documents, shares

# set docs_url="/docs" while developing; keep None in production
app = FastAPI(title="DocShare", docs_url="/docs", redoc_url=None)

app.include_router(auth.router)
app.include_router(documents.router)
app.include_router(shares.router)
app.include_router(admin.router)
app.mount("/ui", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="ui")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ui/")


@app.on_event("startup")
def create_tables():
    Base.metadata.create_all(bind=engine)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    if request.url.path.startswith("/ui"):      # the test UI: no inline or foreign scripts
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' blob:; frame-src blob:; "
            "object-src 'none'; base-uri 'none'; form-action 'self'")
    return resp


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    return JSONResponse({"detail": "Internal error"}, status_code=500)


@app.get("/health")
def health():
    return {"status": "ok"}
