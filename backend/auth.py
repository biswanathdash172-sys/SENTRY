"""
auth.py
-------
Core auth primitives for SENTRY: password hashing, JWT issuance/
verification, and an in-memory user store — all stdlib only (no
compiled deps, no new entries in requirements.txt).

Design goals (mirrors store.py's "demo-safe, drop-in upgrade path"
philosophy):
  - Passwords are NEVER stored or logged in plaintext. Hashed with
    PBKDF2-HMAC-SHA256 (hashlib.pbkdf2_hmac), 200k iterations, a random
    16-byte salt per user. This is stdlib-only — no bcrypt/argon2
    compiled wheel required, so the app never fails to boot because a
    native dependency didn't build.
  - JWTs are hand-rolled HS256 (header.payload.signature, base64url,
    hmac-sha256 signature) — stdlib only (hmac, hashlib, base64, json),
    no PyJWT dependency needed for this small a surface area.
  - USERS is an in-memory dict, same pattern as store.py's STORE dict:
    swap for a real users table later without changing the router.
  - A demo user is seeded on import so the existing frontend hardcoded
    credentials (admin@sentry.io / sentry123, see frontend/login.html)
    keep working against the *real* auth path once main.py's /login is
    wired to this module instead of the old "accept anything" stub.

Usage from routers:
    from auth import (
        create_user, authenticate_user, get_user,
        create_access_token, decode_access_token,
    )
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256, stdlib only)
# ---------------------------------------------------------------------------
_PBKDF2_ITERATIONS = 200_000
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    """Return 'pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>'."""
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time comparison against a hash produced by hash_password()."""
    try:
        algo, iterations_s, salt_hex, hash_hex = stored_hash.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False

    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(candidate, expected)


# ---------------------------------------------------------------------------
# JWT (hand-rolled HS256, stdlib only)
# ---------------------------------------------------------------------------
# Demo-safe default so the app NEVER fails to boot because an env var is
# missing — same philosophy as config.py. Override with JWT_SECRET in any
# real deployment.
JWT_SECRET = os.environ.get("JWT_SECRET", "sentry-demo-insecure-secret-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = int(os.environ.get("JWT_EXPIRY_SECONDS", str(24 * 60 * 60)))  # 24h


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def create_access_token(subject: str, extra_claims: Optional[dict] = None) -> str:
    """Issue a signed HS256 JWT for `subject` (the username)."""
    now = int(time.time())
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + JWT_EXPIRY_SECONDS,
        **(extra_claims or {}),
    }
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


class TokenError(Exception):
    """Raised for any invalid/expired/tampered token — routers turn this into a 401."""


def decode_access_token(token: str) -> dict:
    """Verify signature + expiry and return the payload dict, or raise TokenError."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError:
        raise TokenError("Malformed token")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        actual_sig = _b64url_decode(signature_b64)
    except Exception:
        raise TokenError("Malformed token signature")

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise TokenError("Invalid token signature")

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        raise TokenError("Malformed token payload")

    if payload.get("exp", 0) < int(time.time()):
        raise TokenError("Token expired")

    return payload


# ---------------------------------------------------------------------------
# In-memory user store (same pattern as store.py's STORE dict)
# ---------------------------------------------------------------------------
@dataclass
class User:
    username: str
    password_hash: str
    role: str = "analyst"
    created_at: float = field(default_factory=time.time)


USERS: dict[str, User] = {}


def create_user(username: str, password: str, role: str = "analyst") -> User:
    if username in USERS:
        raise ValueError(f"User '{username}' already exists")
    user = User(username=username, password_hash=hash_password(password), role=role)
    USERS[username] = user
    return user


def get_user(username: str) -> Optional[User]:
    return USERS.get(username)


def authenticate_user(username: str, password: str) -> Optional[User]:
    user = USERS.get(username)
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def _seed_demo_user() -> None:
    """
    Seed the demo user so the existing hardcoded frontend credentials
    (frontend/login.html: admin@sentry.io / sentry123) keep working once
    /login is wired to real auth instead of the old accept-anything stub.
    """
    if "admin@sentry.io" not in USERS:
        create_user("admin@sentry.io", "sentry123", role="admin")


_seed_demo_user()
