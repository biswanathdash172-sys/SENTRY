import pytest
from fastapi.testclient import TestClient
from main import app
from routers.org_auth import create_access_token
from db import database as db

client = TestClient(app)

def _get_token(employee_id: str, org_id: str, is_admin: bool = True) -> str:
    return create_access_token(
        subject=employee_id,
        extra_claims={
            "org_id": org_id,
            "employee_id": employee_id,
            "is_admin": is_admin,
            "is_cyber_head": False,
        },
    )


            
def test_action_state_machine_double_approve(monkeypatch):
    # Mock _get_flag_or_404 to return pending on first call, completed on second
    call_count = {"count": 0}
    def mock_get_flag(*args, **kwargs):
        if call_count["count"] == 0:
            call_count["count"] += 1
            return {"id": "flag_1", "org_id": "Org A", "status": "pending", "tier": "high"}
        else:
            return {"id": "flag_1", "org_id": "Org A", "status": "completed", "tier": "high"}

    monkeypatch.setattr("routers.risk_actions._get_flag_or_404", mock_get_flag)
    
    # Mock supabase client to not actually hit DB
    class MockTable:
        def insert(self, *args, **kwargs): return self
        def update(self, *args, **kwargs): return self
        def eq(self, *args, **kwargs): return self
        def execute(self, *args, **kwargs):
            class Result:
                data = [{"id": "flag_1", "status": "completed", "resolution": "admin_approved", "approved_by": "emp_1", "approved_at": "now"}]
            return Result()
            
    class MockClient:
        def table(self, name): return MockTable()
        
    monkeypatch.setattr("services.supabase_service._get_client", lambda: MockClient())

    token = _get_token("emp_1", "Org A", True)
    
    # First call: pending -> completed
    res1 = client.post("/risk-flags/flag_1/approve", headers={"Authorization": f"Bearer {token}"})
    assert res1.status_code == 200
    
    # Second call: completed -> approve (invalid transition)
    res2 = client.post("/risk-flags/flag_1/approve", headers={"Authorization": f"Bearer {token}"})
    assert res2.status_code == 400
    assert "Invalid transition" in res2.text or "already been resolved" in res2.text

def test_action_state_machine_deny_after_completed(monkeypatch):
    def mock_get_flag(*args, **kwargs):
        return {"id": "flag_1", "org_id": "Org A", "status": "completed", "tier": "high"}
        
    monkeypatch.setattr("routers.risk_actions._get_flag_or_404", mock_get_flag)
    
    token = _get_token("emp_1", "Org A", True)
    res = client.post("/risk-flags/flag_1/deny", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 400
