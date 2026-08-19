"""
main.py
-------
SENTRY demo backend — Human-Governed Autonomous SOC with integrated media
integrity checks.

  * In-memory store instead of Postgres (see models.py docstring for the
    drop-in upgrade path).
  * Polling-friendly REST endpoints instead of a WebSocket (see
    routers/stream.py for the documented, not-yet-wired upgrade path).
  * Every mutating endpoint is wrapped so a bad request returns a clean
    4xx instead of a 500 — the app must never crash mid-demo.

REFACTORED (modular router split): route handlers now live in
routers/alerts.py, routers/actions.py, and routers/media_verify.py
instead of all being defined directly on `app` here. This file is now
just: app setup, static frontend serving, auth stub, health check, and
router registration. Behavior is unchanged — every endpoint below has
the exact same path, method, and logic as before, just relocated.
The shared STORE dict + DB bootstrap moved to store.py so routers can
import it without a circular import back to main.py.

Run:
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000

Then open ../frontend/index.html directly in a browser (it talks to
http://localhost:8000 by default).
"""

from fastapi import FastAPI, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import pathlib

from routers import alerts, actions, media_verify, admin_auth
from store import STORE  # noqa: F401 — imported so /health can report STORE size
from backend.db.json_store import JSONStore
from services.email_poller import EmailPoller

store = JSONStore()
email_poller = EmailPoller()

app = FastAPI(title="SENTRY API", version="0.3.0-demo")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router)
app.include_router(actions.router)
app.include_router(media_verify.router)
# register admin auth router
app.include_router(admin_auth.router)

# Serve the static frontend from the project's frontend/ directory. Mounts are always registered; when files are missing a helpful JSON is returned.
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
_FRONTEND_DIR = _PROJECT_ROOT / "frontend"
# Mount frontend directory at /static so assets can be fetched from /static/...
app.mount("/static", StaticFiles(directory=str(_FRONTEND_DIR)), name="static")
_ASSETS_DIR = _FRONTEND_DIR / "assets"
app.mount("/assets", StaticFiles(directory=str(_ASSETS_DIR)), name="assets")


@app.get("/", include_in_schema=False)
def _serve_frontend_index():
    index_path = _FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"detail": "Frontend index.html not found; API is available under /docs"}


@app.get('/login', include_in_schema=False)
def _serve_login_page():
    login_path = _FRONTEND_DIR / 'login.html'
    if login_path.exists():
        return FileResponse(str(login_path))
    return {"detail": "Login page not found"}


@app.get('/dashboard', include_in_schema=False)
def _serve_dashboard_page():
    dashboard_path = _FRONTEND_DIR / 'dashboard.html'
    if dashboard_path.exists():
        return FileResponse(str(dashboard_path))
    return {"detail": "Dashboard page not found"}


@app.post('/login')
def _login(username: str = Form(...), password: str = Form(...)):
    # Demo-only: accept any credentials and return a demo token
    token = f"demo-token-{username}"
    return {"status": "ok", "user": username, "token": token}


@app.get("/health")
def health():
    return {"status": "ok", "alerts_in_store": len(STORE)}
