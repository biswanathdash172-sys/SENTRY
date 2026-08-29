"""
scripts/verify_auto_approval.py
---------------------------------
Real, live end-to-end test against YOUR ACTUAL RUNNING BACKEND. No mocks,
no fixtures — every call below is a genuine HTTP request to your real
FastAPI server and your real Supabase database.

WHAT THIS PROVES: that a genuinely low-risk finding (confidence=0.1,
guaranteed by classify_confidence()'s real band logic to land in
not_risky) actually gets auto-approved by the system with ZERO human
clicks — i.e. risk_flags.status flips to "completed" and
resolution="auto_approved" purely from can_auto_approve() logic.

This uses POST /ingest/notification as the test vector because it's the
one endpoint where WE control the exact confidence score directly (SCA
scans depend on whatever OSV.dev returns for a given package, which we
can't force to a specific tier on demand). This is still a 100% real
code path — the same endpoint your real notification_poller.py calls —
we're just supplying a controlled, real input value to it, the same way
a QA engineer would send a specific real request to test a specific
real branch of real logic.

USAGE:
    python scripts/verify_auto_approval.py

REQUIRES (same as the rest of this project):
    pip install requests

Run this from the backend/ directory, or set SENTRY_API_BASE if your
server isn't on localhost:8000.
"""

import os
import sys
import requests

API_BASE = os.environ.get("SENTRY_API_BASE", "http://localhost:8000")


def fail(msg: str):
    print(f"\n❌ FAILED: {msg}")
    sys.exit(1)


def ok(msg: str):
    print(f"✅ {msg}")


def main():
    employee_id = input("Employee ID to log in as: ").strip()
    password = input("Password: ").strip()

    print(f"\n--- Step 1: Real login against {API_BASE} ---")
    login_resp = requests.post(
        f"{API_BASE}/login",
        data={"employee_id": employee_id, "password": password},
        timeout=10,
    )
    if login_resp.status_code != 200:
        fail(f"Login failed ({login_resp.status_code}): {login_resp.text}")

    login_data = login_resp.json()
    token = login_data["token"]
    org_id = login_data["org_id"]
    ok(f"Logged in as '{employee_id}' (org: {org_id}, is_admin: {login_data.get('is_admin')})")

    headers = {"Authorization": f"Bearer {token}"}

    print(f"\n--- Step 2: Real check of current auto-approval rules ---")
    rules_resp = requests.get(f"{API_BASE}/rules", headers=headers, timeout=10)
    if rules_resp.status_code == 403:
        fail("This account is not an admin — /rules requires admin. "
             "Log in as an admin account to run this test.")
    if rules_resp.status_code != 200:
        fail(f"GET /rules failed ({rules_resp.status_code}): {rules_resp.text}")

    rules = {r["tier"]: r["can_auto_approve"] for r in rules_resp.json()}
    ok(f"Current rules: {rules}")

    if not rules.get("not_risky"):
        print("\n--- not_risky auto-approve is currently OFF. Turning it ON "
              "for this test (real PUT /rules call) ---")
        put_resp = requests.put(
            f"{API_BASE}/rules", headers=headers,
            json={"tier": "not_risky", "can_auto_approve": True}, timeout=10,
        )
        if put_resp.status_code != 200:
            fail(f"Could not enable not_risky auto-approve: {put_resp.text}")
        ok("not_risky auto-approve is now ON.")
    else:
        ok("not_risky auto-approve is already ON — no change needed.")

    print(f"\n--- Step 3: Submit a REAL controlled finding via POST /ingest/notification ---")
    print("Using confidence=0.1 — classify_confidence() guarantees this lands "
          "in not_risky (band: 0.0-0.39), per the real code in risk_classifier.py.")

    ingest_resp = requests.post(
        f"{API_BASE}/ingest/notification",
        headers=headers,
        json={
            "app_name": "VerificationScript-TestApp",
            "text": "This is a controlled, low-risk test finding submitted by "
                    "verify_auto_approval.py to confirm the auto-approval "
                    "pipeline works end-to-end.",
            "confidence": 0.1,
            "reasons": ["Controlled test input from verify_auto_approval.py"],
            "arrival_time": None,
        },
        timeout=10,
    )
    if ingest_resp.status_code != 200:
        fail(f"POST /ingest/notification failed ({ingest_resp.status_code}): {ingest_resp.text}")

    ingest_data = ingest_resp.json()
    risk_flag_id = ingest_data["risk_flag_id"]
    tier = ingest_data["tier"]
    status = ingest_data["risk_flag_status"]
    resolution = ingest_data.get("resolution")

    ok(f"Finding submitted. risk_flag_id={risk_flag_id}, tier={tier}, "
       f"status={status}, resolution={resolution}")

    print(f"\n--- Step 4: Verify the result ---")
    if tier != "not_risky":
        fail(f"Expected tier='not_risky' but got '{tier}'. classify_confidence() "
             f"may not be behaving as expected — check risk_classifier.py.")
    ok("Tier correctly classified as not_risky.")

    if status != "completed" or resolution != "auto_approved":
        fail(
            f"AUTO-APPROVAL DID NOT FIRE. Expected status='completed' and "
            f"resolution='auto_approved', but got status='{status}', "
            f"resolution='{resolution}'. This means can_auto_approve() in "
            f"risk_classifier.py is not returning True for this org+tier, "
            f"even though the rule is enabled — check Supabase's "
            f"auto_approval_rules table directly for org_id='{org_id}'."
        )
    ok("AUTO-APPROVAL CONFIRMED: status='completed', resolution='auto_approved' "
       "— achieved with ZERO human clicks, purely from real backend logic.")

    print(f"\n--- Step 5: Double-check by re-fetching via GET /scan/results ---")
    results_resp = requests.get(f"{API_BASE}/scan/results", headers=headers, timeout=10)
    if results_resp.status_code != 200:
        fail(f"GET /scan/results failed: {results_resp.text}")

    matching = [r for r in results_resp.json() if r["risk_flag_id"] == risk_flag_id]
    if not matching:
        fail(f"Could not find risk_flag_id={risk_flag_id} in /scan/results — "
             f"the row may not be persisting correctly.")

    row = matching[0]
    ok(f"Confirmed in /scan/results: source_type={row.get('source_type')}, "
       f"app_name={row.get('app_name')}, status={row['risk_flag_status']}, "
       f"resolution={row.get('resolution')}")

    print("\n" + "=" * 70)
    print("ALL CHECKS PASSED — auto-approval pipeline verified end-to-end "
          "against your real running backend and real Supabase database.")
    print("=" * 70)


if __name__ == "__main__":
    main()