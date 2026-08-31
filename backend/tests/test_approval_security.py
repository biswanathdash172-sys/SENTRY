import pytest
from fastapi.testclient import TestClient
from main import app
from routers.org_auth import create_access_token
from db import database as db

client = TestClient(app)

def _get_token(employee_id: str, org_id: str, is_admin: bool = False) -> str:
    return create_access_token(
        subject=employee_id,
        extra_claims={
            "org_id": org_id,
            "employee_id": employee_id,
            "is_admin": is_admin,
            "is_cyber_head": False,
        },
    )

def test_approval_security_no_auth():
    res = client.post("/risk-flags/test-flag-id/approve")
    assert res.status_code == 401

def test_approval_security_non_admin():
    token = _get_token("emp_123", "org_1", is_admin=False)
    res = client.post("/risk-flags/test-flag-id/approve", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403

def test_approval_security_cross_org(monkeypatch):
    # Mock the DB client to return a flag belonging to Org B
    class MockTable:
        def select(self, *args, **kwargs): return self
        def eq(self, *args, **kwargs): return self
        def limit(self, *args, **kwargs): return self
        def execute(self, *args, **kwargs):
            class Result:
                data = [{"id": "test-flag-id", "org_id": "Org B", "status": "pending", "tier": "high"}]
            return Result()
            
    class MockClient:
        def table(self, name): return MockTable()

    monkeypatch.setattr("services.supabase_service._get_client", lambda: MockClient())

    token = _get_token("emp_123", "Org A", is_admin=True) # Admin of Org A
    res = client.post("/risk-flags/test-flag-id/approve", headers={"Authorization": f"Bearer {token}"})
    
    assert res.status_code == 404
