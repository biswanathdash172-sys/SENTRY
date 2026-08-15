"""
config.py
---------
Tiny env-var loader for SENTRY. No external dependency (no python-dotenv
needed) — just os.environ with safe defaults, so the app NEVER fails to
boot because a .env file is missing.

Env vars (see .env.example):
  DATABASE_URL   Postgres connection string, e.g.
                 postgresql://user:pass@localhost:5432/sentry
                 If unset OR unreachable, the app automatically falls
                 back to in-memory storage (DEMO MODE) — see db/database.py.
  DEMO_MODE      "true"/"false". If explicitly set to "true", skips trying
                 the DB entirely and always uses in-memory storage — useful
                 to force the judge-safe fallback on stage regardless of
                 whether a DB happens to be reachable.
"""

import os

DATABASE_URL = os.environ.get("DATABASE_URL", "")
DEMO_MODE_FORCED = os.environ.get("DEMO_MODE", "false").lower() == "true"