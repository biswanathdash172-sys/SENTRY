# Project-root ASGI app that serves the static frontend at / and mounts
# the backend API at /api so both frontend and backend are available on the
# same origin/port when running `uvicorn main:app` from the repo root.

import sys
import importlib.util
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse

_THIS_DIR = Path(__file__).resolve().parent
_BACKEND_DIR = _THIS_DIR / "backend"

# Load backend/main.py as a module (executes its top-level code and registers
# the FastAPI instance as `app` inside that module).
spec = importlib.util.spec_from_file_location("backend_main", str(_BACKEND_DIR / "main.py"))
_backend_mod = importlib.util.module_from_spec(spec)
# Ensure backend/ is on sys.path so backend's relative imports (e.g. `from models import ...`)
# resolve correctly when executing the module from the project root.
import sys
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))
spec.loader.exec_module(_backend_mod)
backend_app = getattr(_backend_mod, "app")

# Create the root FastAPI app that will serve the frontend and delegate API
# requests to the backend app mounted under /api.
app = FastAPI()
app.mount("/api", backend_app)

# Serve the static index.html at the root path
_FRONTEND_INDEX = _THIS_DIR / "frontend" / "index.html"

@app.get("/", include_in_schema=False)
def _serve_index():
    if _FRONTEND_INDEX.exists():
        return FileResponse(str(_FRONTEND_INDEX))
    return {"message": "Frontend not found; API is available under /api"}

__all__ = ["app"]
