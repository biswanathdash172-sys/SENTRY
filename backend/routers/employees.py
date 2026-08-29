"""
routers/employees.py
---------------------
Employee Management module (org-admin requirement).

  POST   /employees                  - create employee (Employee ID, Name, Password)
  GET    /employees                  - list all employees in the caller's org
  PUT    /employees/{employee_id}/admin - promote/revoke admin status
  DELETE /employees/{employee_id}    - remove an employee

ALL routes are ADMIN ONLY (require_admin) and ALWAYS scoped to the
calling admin's own org_id — never a client-supplied org_id — so one
org's admin can never read/modify/delete another organization's staff.

FAIL-SAFE: promoting/revoking/deleting can never leave an org with zero
admins. This is enforced in services/supabase_service.py (the
authoritative, DB-checked guarantee) — the extra guards in this file
against self-action are a UX-friendliness layer on top, not a
replacement for that guarantee.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import List

from models import AdminUser
from routers.org_auth import require_admin
from services.supabase_service import (
    create_employee,
    list_employees,
    set_employee_admin_status,
    delete_employee,
    SupabaseAuthError,
    SupabaseNotConfigured,
)

router = APIRouter(tags=["employees"])


class CreateEmployeeRequest(BaseModel):
    employee_id: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=200)
    password: str = Field(..., min_length=4, max_length=200)


class EmployeeOut(BaseModel):
    employee_id: str
    org_id: str
    name: str
    is_admin: bool


class SetAdminRequest(BaseModel):
    is_admin: bool


@router.post("/employees", response_model=EmployeeOut)
def create_new_employee(req: CreateEmployeeRequest, admin: AdminUser = Depends(require_admin)):
    try:
        employee = create_employee(
            org_id=admin.org_id, employee_id=req.employee_id,
            name=req.name, password=req.password,
        )
    except SupabaseNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except SupabaseAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return EmployeeOut(
        employee_id=employee.employee_id, org_id=employee.org_id,
        name=employee.display_name or employee.employee_id, is_admin=employee.is_admin,
    )


@router.get("/employees", response_model=List[EmployeeOut])
def get_employees(admin: AdminUser = Depends(require_admin)):
    """Real Supabase read of every employee in the caller's org — this is
    what the admin dashboard renders the employee table from."""
    try:
        employees = list_employees(admin.org_id)
    except SupabaseNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except SupabaseAuthError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return [
        EmployeeOut(
            employee_id=e.employee_id, org_id=e.org_id,
            name=e.display_name or e.employee_id, is_admin=e.is_admin,
        )
        for e in employees
    ]


@router.put("/employees/{employee_id}/admin", response_model=EmployeeOut)
def set_admin_status(employee_id: str, req: SetAdminRequest, admin: AdminUser = Depends(require_admin)):
    """
    Promote or revoke admin status. UX guard: an admin revoking their OWN
    status gets a clear, specific error rather than a generic Supabase
    message — but the REAL protection (can this leave zero admins?) is
    enforced inside set_employee_admin_status() regardless of who's
    being changed, so this guard is a nicer message, not the safety net.
    """
    if employee_id == admin.employee_id and not req.is_admin:
        raise HTTPException(
            status_code=400,
            detail="You cannot revoke your own admin status. Ask another "
                   "admin to do this, or promote someone else first.",
        )

    try:
        employee = set_employee_admin_status(admin.org_id, employee_id, req.is_admin)
    except SupabaseNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except SupabaseAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return EmployeeOut(
        employee_id=employee.employee_id, org_id=employee.org_id,
        name=employee.display_name or employee.employee_id, is_admin=employee.is_admin,
    )


@router.delete("/employees/{employee_id}")
def remove_employee(employee_id: str, admin: AdminUser = Depends(require_admin)):
    if employee_id == admin.employee_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot remove your own account while logged in as it.",
        )

    try:
        delete_employee(admin.org_id, employee_id)
    except SupabaseNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except SupabaseAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {"status": "ok", "deleted": employee_id}