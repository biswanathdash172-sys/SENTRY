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
    # Check if employee exists
    existing = client.table("employees").select("employee_id").eq("employee_id", req.user_id).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="User ID already exists.")
    is_cyber_head = False
    is_admin = False
    try:
        data = {
            "org_id": req.org_id,
            "employee_id": req.user_id,
            "display_name": req.name,
            "password": req.password,
            "is_admin": is_admin,
        }
        # Attempt to insert with is_cyber_head if column exists
        try:
            data_with_cyber = {**data, "is_cyber_head": is_cyber_head}
            client.table("employees").insert(data_with_cyber).execute()
        except Exception as e:
            if "Could not find the 'is_cyber_head' column" in str(e) or "is_cyber_head" in str(e):
                logger.warning("is_cyber_head column missing, inserting without it.")
                client.table("employees").insert(data).execute()
            else:
                raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to register user: {e}")
    return {"status": "ok", "message": f"Employee {req.name} registered successfully. You can now login."}

@router.post("/signup")
def role_based_signup(req: SignupRequest):
    try:
        client = _get_client()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Supabase not available: {exc}")

    if req.role == "organization":
        # Check if org exists
        existing = client.table("organizations").select("org_id").eq("org_id", req.user_id).execute()
        if existing.data:
            raise HTTPException(status_code=400, detail="Organization ID already exists.")
        
        # Insert
        try:
            client.table("organizations").insert({
                "org_id": req.user_id,
                "org_name": req.name,
                "org_password": req.password
            }).execute()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to register organization: {e}")
        
        return {"status": "ok", "message": f"Organization {req.name} registered successfully. You can now login."}

    elif req.role in ["cyber_head", "employee"]:
        if not req.org_id:
            raise HTTPException(status_code=400, detail="org_id is required for employees and Cyber Heads.")
        
        # Check if org exists
        org_check = client.table("organizations").select("org_id").eq("org_id", req.org_id).execute()
        if not org_check.data:
            raise HTTPException(status_code=400, detail=f"Organization {req.org_id} does not exist.")
            
        # Check if employee exists
        existing = client.table("employees").select("employee_id").eq("employee_id", req.user_id).execute()
        if existing.data:
            raise HTTPException(status_code=400, detail="User ID already exists.")
            
        is_cyber_head = (req.role == "cyber_head")
        is_admin = (req.role == "cyber_head") # Usually Cyber Heads are admins too, or maybe just is_cyber_head
        
        # For simplicity, if they register as cyber_head, we set both to true.
        try:
            data = {
                "org_id": req.org_id,
                "employee_id": req.user_id,
                "display_name": req.name,
                "password": req.password,
                "is_admin": is_admin
            }
            # Add is_cyber_head if the schema supports it. If it fails, fallback.
            try:
                data_with_cyber = {**data, "is_cyber_head": is_cyber_head}
                client.table("employees").insert(data_with_cyber).execute()
            except Exception as e:
                if "Could not find the 'is_cyber_head' column" in str(e) or "is_cyber_head" in str(e):
                    # Schema not migrated yet, insert without it (it won't be a true cyber head, but registration succeeds)
                    logger.warning("is_cyber_head column missing, inserting without it.")
                    client.table("employees").insert(data).execute()
                else:
                    raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to register user: {e}")
            
        return {"status": "ok", "message": f"{req.role.replace('_', ' ').title()} {req.name} registered successfully. You can now login."}
    else:
        raise HTTPException(status_code=400, detail="Invalid role specified.")
