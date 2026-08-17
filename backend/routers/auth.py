"""
routers/auth.py
----------------
Real authentication routes, replacing the old "accept any credentials"
stub that used to live directly on `app` in main.py.

  POST /login       - SAME path/contract as before (Form username +
                       password -> {"status","user","token"}), but now
                       backed by real PBKDF2 hashing + a signed JWT
                       instead of `f"demo-token-{username}"`.
  POST /auth/register - create a new user (hashed password, never
                       stored/returned in plaintext).
  GET  /auth/me      - protected route; proves the Bearer token issued
                       by /login round-trips correctly.

Kept separate from routers/alerts.py & routers/actions.py since this is
identity/session concern, not alert-lifecycle concern.
"""

from fastapi import APIRouter, Form, HTTPException, Header
from pydantic import BaseModel

from auth import (
    authenticate_user,
    create_user,
    create_access_token,
    decode_access_token,
    get_user,
    TokenError,
)

router = APIRouter(tags=["auth"])


class RegisterRequest(BaseModel):
    username: str
    password: str


class RegisterResponse(BaseModel):
    status: str
    user: str


class MeResponse(BaseModel):
    username: str
    role: str


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    return authorization.split(" ", 1)[1].strip()


@router.post("/auth/register", response_model=RegisterResponse)
def register(payload: RegisterRequest):
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    try:
        create_user(payload.username, payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"status": "ok", "user": payload.username}


@router.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    """
    Same request/response contract as the original demo stub:
    Form(username, password) -> {"status": "ok", "user": ..., "token": ...}
    Now backed by real hashing + a real signed JWT instead of a fake
    'demo-token-{username}' string.
    """
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_access_token(subject=user.username, extra_claims={"role": user.role})
    return {"status": "ok", "user": user.username, "token": token}


@router.get("/auth/me", response_model=MeResponse)
def me(authorization: str | None = Header(default=None)):
    token = _extract_bearer_token(authorization)
    try:
        payload = decode_access_token(token)
    except TokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    username = payload.get("sub")
    user = get_user(username) if username else None
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")

    return {"username": user.username, "role": user.role}
