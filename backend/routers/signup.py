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

from services.risk_classifier import ensure_default_rules

@router.post("/signup/organization")
def signup_organization(req: SignupRequest):
    # Validate role
    if req.role != "organization":
        raise HTTPException(status_code=400, detail="Role must be 'organization' for this endpoint.")
    
    org_id = req.user_id.strip()
    org_name = req.name.strip()
    password = req.password
    
    if not org_id or not org_name or not password:
        raise HTTPException(status_code=400, detail="Organization ID, Name, and Password are all required.")

    try:
        client = _get_client()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Supabase not available: {exc}")

    # Check if org exists in Supabase
    try:
        existing = client.table("organizations").select("org_id").eq("org_id", org_id).limit(1).execute()
        if existing.data:
            raise HTTPException(status_code=400, detail=f"Organization ID '{org_id}' already exists.")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to check existing organization: {e}")

    # 1. Insert into organizations table
    try:
        client.table("organizations").insert({
            "org_id": org_id,
            "org_name": org_name,
            "org_password": password,
        }).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register organization in database: {e}")

    # 2. Automatically ensure default auto-approval rules exist for this org
    try:
        ensure_default_rules(org_id)
    except Exception as e:
        logger.warning(f"Could not ensure default rules for {org_id}: {e}")

    # 3. Create initial Admin account in employees table
    try:
        emp_existing = client.table("employees").select("employee_id").eq("employee_id", org_id).limit(1).execute()
        if not emp_existing.data:
            client.table("employees").insert({
                "employee_id": org_id,
                "org_id": org_id,
                "display_name": org_name,
                "password": password,
                "is_admin": True,
                "is_cyber_head": False,
            }).execute()
    except Exception as e:
        logger.warning(f"Could not bootstrap initial admin employee for {org_id}: {e}")

    return {
        "status": "ok",
        "org_id": org_id,
        "org_name": org_name,
        "message": f"Organization '{org_name}' registered successfully. You can now log in.",
    }

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

