from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from services.supabase_service import _get_client
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["signup"])

class SignupRequest(BaseModel):
    role: str # "organization", "cyber_head", "employee"
    user_id: str # org_id if organization, employee_id otherwise
    name: str
    password: str
    org_id: Optional[str] = None # required if cyber_head or employee

@router.post("/signup/organization")
def signup_organization(req: SignupRequest):
    # role is ignored, expect only organization data
    if req.role != "organization":
        raise HTTPException(status_code=400, detail="Role must be 'organization' for this endpoint.")
    # Reuse existing logic
    try:
        client = _get_client()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Supabase not available: {exc}")
    # Check if org exists
    existing = client.table("organizations").select("org_id").eq("org_id", req.user_id).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Organization ID already exists.")
    try:
        client.table("organizations").insert({
            "org_id": req.user_id,
            "org_name": req.name,
            "org_password": req.password,
        }).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register organization: {e}")
    return {"status": "ok", "message": f"Organization {req.name} registered successfully. You can now login."}

@router.post("/signup/employee")
def signup_employee(req: SignupRequest):
    # Expect role to be 'employee' (ignore if not)
    if req.role != "employee":
        raise HTTPException(status_code=400, detail="Role must be 'employee' for this endpoint.")
    if not req.org_id:
        raise HTTPException(status_code=400, detail="org_id is required for employee signup.")
    try:
        client = _get_client()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Supabase not available: {exc}")
    # Verify organization exists
    org_check = client.table("organizations").select("org_id").eq("org_id", req.org_id).execute()
    if not org_check.data:
        raise HTTPException(status_code=400, detail=f"Organization {req.org_id} does not exist.")
    
    from services.supabase_service import create_employee, SupabaseAuthError
    try:
        create_employee(
            org_id=req.org_id,
            employee_id=req.user_id,
            name=req.name,
            password=req.password
        )
    except SupabaseAuthError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register user: {e}")
    return {"status": "ok", "message": f"Employee {req.name} registered successfully. You can now login."}

