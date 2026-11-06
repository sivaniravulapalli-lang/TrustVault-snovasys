import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import auth
from .config import ENABLE_DOCS, MAX_REQUEST_BYTES
from .db import add_missing_columns, engine
from .maintenance import get_maintenance_status, check_and_notify_scheduled_expiry
from .models import Base
from .routes import admin, documents, mailbox, shares, telegram


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    add_missing_columns()

    async def _maintenance_monitor():
        while True:
            try:
                check_and_notify_scheduled_expiry()
            except Exception:
                pass
            await asyncio.sleep(5)

    monitor_task = asyncio.create_task(_maintenance_monitor())
    try:
        yield
    finally:
        monitor_task.cancel()


# /docs and /openapi.json exist only when ENABLE_DOCS=1 (your own machine)
app = FastAPI(title="TrustVault", lifespan=lifespan, redoc_url=None,
              docs_url="/docs" if ENABLE_DOCS else None,
              openapi_url="/openapi.json" if ENABLE_DOCS else None)

app.include_router(auth.router)
app.include_router(documents.router)
app.include_router(shares.router)
app.include_router(admin.router)
app.include_router(telegram.router)
app.include_router(mailbox.router)
app.mount("/ui", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="ui")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ui/")


@app.get("/maintenance/status")
def maintenance_status():
    return get_maintenance_status()


def refuse_oversized(request: Request):
    """Turn away huge or unsized bodies before the server reads them."""
    if request.method not in ("POST", "PUT", "PATCH"):
        return None
    try:
        size = int(request.headers.get("content-length", "0"))
    except ValueError:
        return JSONResponse({"detail": "Bad Content-Length"}, status_code=400)
    if size > MAX_REQUEST_BYTES:
        return JSONResponse({"detail": "The file is larger than 10 MB, the maximum allowed."},
                            status_code=413)
    if "chunked" in request.headers.get("transfer-encoding", "").lower():
        return JSONResponse({"detail": "Content-Length required"}, status_code=411)
    return None


@app.middleware("http")
async def guard_and_headers(request: Request, call_next):
    resp = refuse_oversized(request) or await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["Cache-Control"] = "no-store"
    if request.url.path.startswith("/ui"):      # the test UI: no inline or foreign scripts
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; font-src 'self' https://fonts.gstatic.com; "
            "style-src 'self' https://fonts.googleapis.com; "
            "img-src 'self' blob: data:; frame-src blob:; "
            "object-src 'none'; base-uri 'none'; form-action 'self'")
    return resp


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    return JSONResponse({"detail": "Internal error"}, status_code=500)


@app.get("/health")
def health():
    return {"status": "ok"}
