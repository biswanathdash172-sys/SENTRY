"""
routers/admin_auth.py
----------------------
Invite-only admin registration + real login, completely separate from the
existing analyst-dashboard demo `/login` in main.py.

  POST /admin/register  -> creates one Org + its one Admin (invite-only)
  POST /admin/login     -> returns a JWT
  get_current_admin     -> FastAPI dependency other routers use to figure
                            out which org's alerts an admin is allowed to see
"""

from fastapi import APIRouter, HTTPException, Header
from typing import Optional

from models import AdminRegisterRequest, AdminLoginRequest, AdminAuthResponse, AdminUser
from services import auth_service

router = APIRouter(prefix="/admin", tags=["admin-auth"])


@router.post("/register", response_model=AdminAuthResponse)
def register(req: AdminRegisterRequest):
    try:
        org, admin = auth_service.register_admin(
            invite_code=req.invite_code,
            org_name=req.org_name,
            monitored_mailbox=req.monitored_mailbox,
            username=req.username,
            password=req.password,
        )
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    token = auth_service.create_token(admin)
    return AdminAuthResponse(token=token, org_id=org.id, username=admin.username)


@router.post("/login", response_model=AdminAuthResponse)
def login(req: AdminLoginRequest):
    try:
        admin = auth_service.authenticate(req.username, req.password)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    token = auth_service.create_token(admin)
    return AdminAuthResponse(token=token, org_id=admin.org_id, username=admin.username)


def get_current_admin(authorization: Optional[str] = Header(default=None)) -> AdminUser:
    """Dependency: reads `Authorization: Bearer <token>`, returns the AdminUser.
    Raises 401 if missing/invalid — routers use this to scope data by org_id."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token.")
    token = authorization.split(" ", 1)[1].strip()
    try:
        return auth_service.get_admin_from_token(token)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
