from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from services.auth_service import AuthService
from db.json_store import JSONStore
from jose import jwt

router = APIRouter(tags=["admin"])

_auth_service = AuthService()
_store = JSONStore()


class RegisterRequest(BaseModel):
    invite_code: Optional[str] = None
    org_id: int
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/admin/register")
def register_admin(req: RegisterRequest):
    admin = _auth_service.create_admin(req.invite_code or "", req.org_id, req.username, req.password)
    return admin


@router.post("/admin/login")
def login_admin(req: LoginRequest):
    token = _auth_service.authenticate(req.username, req.password)
    if token:
        return {"access_token": token}
    raise HTTPException(status_code=401, detail="Invalid username or password")


@router.get("/admin/current")
def get_current_admin(token: str):
    try:
        payload = _auth_service.decode_token(token)
        admin_id = payload.get("admin_id")
        admins = _store.load_admins() or []
        for a in admins:
            if a.get("id") == admin_id:
                return a
        raise HTTPException(status_code=404, detail="Admin not found")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
