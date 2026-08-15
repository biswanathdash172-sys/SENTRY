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

# Use the backend app directly so running `uvicorn main:app` from the
# repository root behaves the same as running the backend from its folder.
app = backend_app

__all__ = ["app"]
