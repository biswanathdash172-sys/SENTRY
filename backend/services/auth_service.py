import os
from datetime import datetime, timedelta
from typing import Optional

from passlib.hash import bcrypt
from jose import jwt

from backend.db.json_store import JSONStore


class AuthService:
    def __init__(self, store: Optional[JSONStore] = None):
        self.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
        self.store = store or JSONStore()
        # token lifetime (optional)
        self.token_exp_minutes = int(os.environ.get("TOKEN_EXP_MINUTES", "1440"))

    def create_admin(self, invite_code: str, org_id: int, username: str, password: str):
        admins = self.store.load_admins() or []
        next_id = 1 + max((a.get("id", 0) for a in admins), default=0)
        hashed_password = bcrypt.hash(password)
        admin = {
            "id": next_id,
            "org_id": org_id,
            "username": username,
            "password_hash": hashed_password,
            "created_at": datetime.utcnow().isoformat(),
        }
        admins.append(admin)
        self.store.save_admins(admins)
        return admin

    def authenticate(self, username: str, password: str) -> Optional[str]:
        admins = self.store.load_admins() or []
        for a in admins:
            if a.get("username") == username:
                try:
                    if bcrypt.verify(password, a.get("password_hash", "")):
                        payload = {
                            "admin_id": a["id"],
                            "org_id": a["org_id"],
                            "exp": datetime.utcnow() + timedelta(minutes=self.token_exp_minutes),
                        }
                        token = jwt.encode(payload, self.secret_key, algorithm="HS256")
                        return token
                except Exception:
                    # any verification error -> treat as auth failure
                    return None
        return None

    def decode_token(self, token: str):
        return jwt.decode(token, self.secret_key, algorithms=["HS256"])