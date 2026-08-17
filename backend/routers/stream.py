"""
routers/stream.py
------------------
STATUS: NOT IMPLEMENTED — placeholder, not wired into main.py.

main.py's own module docstring is explicit about this: "Polling-friendly
REST endpoints instead of a WebSocket." The frontend currently gets live
updates by polling GET /alerts on an interval (see frontend/src/hooks/
useWebSocket.js and useAlerts.js for where a real implementation would
plug in on the frontend side).

This file exists as the documented, obvious place to add a real
WebSocket endpoint later, matching the pattern used elsewhere in this
codebase (e.g. backend/ai/deepfake_detector.py's PretrainedModelBackend
stub) — a clearly-labeled TODO in code, not just a claim in a doc file.

WHAT A REAL IMPLEMENTATION WOULD NEED:
  1. A FastAPI @router.websocket("/ws/alerts") endpoint that accepts a
     connection and keeps it open.
  2. A simple in-process pub/sub (e.g. a list of active WebSocket
     connections, or an asyncio.Queue per connection) that routers/
     alerts.py and routers/actions.py broadcast to whenever STORE is
     mutated (new alert, approve/deny, resolve) — mirroring exactly the
     mutation points that already call db.save_alert(alert) today.
  3. Frontend swap from setInterval-based polling to a WebSocket
     `onmessage` handler in useWebSocket.js.

Until then, calling this module does nothing — it is intentionally not
imported by main.py, so it can't be mistaken for working code that just
isn't wired up correctly. Polling remains the real, working mechanism.
"""