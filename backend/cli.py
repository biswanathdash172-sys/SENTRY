"""
backend/cli.py
--------------
Management CLI utility for SENTRY administrators and operators.

Commands:
  python cli.py status
      Shows high-level status: DB connection, organizations, employees, active freezes.

  python cli.py set-cyber-head <employee_id> [--enable | --disable]
      Grants or revokes the is_cyber_head flag for an employee in Supabase.

  python cli.py set-admin <employee_id> [--enable | --disable]
      Grants or revokes the is_admin flag for an employee in Supabase.

  python cli.py freeze <employee_id> [--reason "text"] [--by "admin"]
      Immediately queues a silent device freeze order for an employee.

  python cli.py unfreeze <employee_id> [--by "admin"]
      Lifts all active freeze orders for an employee.

  python cli.py add-domain <org_id> <domain>
      Adds a domain to an organization's trusted whitelist.

  python cli.py list-domains <org_id>
      Lists all trusted sender domains for an organization.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure backend root is on sys.path
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
load_dotenv(_HERE / ".env")


def _get_db():
    from services.supabase_service import _get_client
    return _get_client()


def cmd_status(args):
    client = _get_db()
    print("========================================")
    print("        SENTRY System Status")
    print("========================================")

    # Orgs
    try:
        orgs = client.table("organizations").select("org_id, org_name").execute().data or []
        print(f"\n[+] Organizations ({len(orgs)}):")
        for o in orgs:
            print(f"    - {o.get('org_id')}: {o.get('org_name')}")
    except Exception as e:
        print(f"[-] Could not list organizations: {e}")

    # Employees
    try:
        emps = client.table("employees").select("employee_id, org_id, is_admin, is_cyber_head").execute().data or []
        print(f"\n[+] Employees ({len(emps)}):")
        for emp in emps:
            roles = []
            if emp.get("is_admin"):
                roles.append("Admin")
            if emp.get("is_cyber_head"):
                roles.append("Cyber Head")
            role_str = f"[{', '.join(roles)}]" if roles else "[Employee]"
            print(f"    - {emp.get('employee_id')} ({emp.get('org_id')}): {role_str}")
    except Exception as e:
        # If is_cyber_head column doesn't exist yet, fallback
        try:
            emps = client.table("employees").select("employee_id, org_id, is_admin").execute().data or []
            print(f"\n[+] Employees ({len(emps)}):")
            for emp in emps:
                role_str = "[Admin]" if emp.get("is_admin") else "[Employee]"
                print(f"    - {emp.get('employee_id')} ({emp.get('org_id')}): {role_str}")
            print("    (Note: is_cyber_head column not yet migrated in Supabase)")
        except Exception as e2:
            print(f"[-] Could not list employees: {e2}")

    # Active Freezes
    try:
        freezes = client.table("device_freeze_requests").select("employee_id, org_id, reason, status").eq("status", "active").execute().data or []
        print(f"\n[+] Active Device Freezes ({len(freezes)}):")
        for f in freezes:
            print(f"    - {f.get('employee_id')} ({f.get('org_id')}): {f.get('reason')}")
    except Exception as e:
        print(f"[-] Could not query device_freeze_requests (table may not be created yet): {e}")

    print("\n========================================")


def cmd_set_cyber_head(args):
    client = _get_db()
    emp_id = args.employee_id
    enable = not args.disable

    try:
        res = client.table("employees").update({"is_cyber_head": enable}).eq("employee_id", emp_id).execute()
        if not res.data:
            print(f"[-] Employee '{emp_id}' not found.")
            return
        status_str = "ENABLED" if enable else "DISABLED"
        print(f"[+] Successfully set is_cyber_head={status_str} for employee '{emp_id}'.")
    except Exception as e:
        print(f"[-] Failed to update employee: {e}")
        print("    If column does not exist, run backend/db/migration_v0.6.0.sql in Supabase SQL editor.")


def cmd_set_admin(args):
    client = _get_db()
    emp_id = args.employee_id
    enable = not args.disable

    try:
        res = client.table("employees").update({"is_admin": enable}).eq("employee_id", emp_id).execute()
        if not res.data:
            print(f"[-] Employee '{emp_id}' not found.")
            return
        status_str = "ENABLED" if enable else "DISABLED"
        print(f"[+] Successfully set is_admin={status_str} for employee '{emp_id}'.")
    except Exception as e:
        print(f"[-] Failed to update employee: {e}")


def cmd_freeze(args):
    from services.device_freeze_service import trigger_freeze
    client = _get_db()
    emp_id = args.employee_id

    # Lookup employee org
    res = client.table("employees").select("org_id").eq("employee_id", emp_id).limit(1).execute()
    if not res.data:
        print(f"[-] Employee '{emp_id}' not found.")
        return

    org_id = res.data[0]["org_id"]
    try:
        freeze = trigger_freeze(
            org_id=org_id,
            employee_id=emp_id,
            reason=args.reason or "CLI manual lockdown",
            triggered_by=args.by or "cli_admin",
        )
        print(f"[+] Silent freeze order queued for '{emp_id}' (Org: {org_id}). Freeze ID: {freeze.get('id')}")
    except Exception as e:
        print(f"[-] Failed to freeze device: {e}")


def cmd_unfreeze(args):
    from services.device_freeze_service import lift_freeze
    client = _get_db()
    emp_id = args.employee_id

    res = client.table("employees").select("org_id").eq("employee_id", emp_id).limit(1).execute()
    if not res.data:
        print(f"[-] Employee '{emp_id}' not found.")
        return

    org_id = res.data[0]["org_id"]
    try:
        lift_freeze(org_id=org_id, employee_id=emp_id, lifted_by=args.by or "cli_admin")
        print(f"[+] Device freeze lifted for '{emp_id}' (Org: {org_id}).")
    except Exception as e:
        print(f"[-] Failed to lift freeze: {e}")


def cmd_add_domain(args):
    client = _get_db()
    org_id = args.org_id
    domain = args.domain.strip().lower().lstrip("@")

    try:
        res = client.table("domain_whitelist").insert({
            "org_id": org_id,
            "domain": domain,
            "added_by": "cli_admin",
        }).execute()
        print(f"[+] Domain '@{domain}' added to trusted whitelist for org '{org_id}'.")
    except Exception as e:
        print(f"[-] Failed to add domain: {e}")


def cmd_list_domains(args):
    from services.domain_verifier import get_trusted_domains
    domains = get_trusted_domains(args.org_id)
    print(f"[+] Trusted domains for org '{args.org_id}':")
    if not domains:
        print("    (None configured)")
    for d in domains:
        print(f"    - @{d}")


def main():
    parser = argparse.ArgumentParser(description="SENTRY Management CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    p_status = subparsers.add_parser("status", help="Show system status")
    p_status.set_defaults(func=cmd_status)

    # set-cyber-head
    p_cyber = subparsers.add_parser("set-cyber-head", help="Grant/Revoke Cyber Head role")
    p_cyber.add_argument("employee_id", help="Employee ID (e.g. EMP-0001)")
    p_cyber.add_argument("--disable", action="store_true", help="Revoke Cyber Head role")
    p_cyber.set_defaults(func=cmd_set_cyber_head)

    # set-admin
    p_admin = subparsers.add_parser("set-admin", help="Grant/Revoke Org Admin role")
    p_admin.add_argument("employee_id", help="Employee ID (e.g. EMP-0001)")
    p_admin.add_argument("--disable", action="store_true", help="Revoke Admin role")
    p_admin.set_defaults(func=cmd_set_admin)

    # freeze
    p_freeze = subparsers.add_parser("freeze", help="Queue silent device freeze")
    p_freeze.add_argument("employee_id", help="Employee ID to freeze")
    p_freeze.add_argument("--reason", default="Manual security lockdown", help="Reason for freeze")
    p_freeze.add_argument("--by", default="cli_admin", help="Initiator identifier")
    p_freeze.set_defaults(func=cmd_freeze)

    # unfreeze
    p_unfreeze = subparsers.add_parser("unfreeze", help="Lift device freeze")
    p_unfreeze.add_argument("employee_id", help="Employee ID to unfreeze")
    p_unfreeze.add_argument("--by", default="cli_admin", help="Initiator identifier")
    p_unfreeze.set_defaults(func=cmd_unfreeze)

    # add-domain
    p_add_dom = subparsers.add_parser("add-domain", help="Add domain to whitelist")
    p_add_dom.add_argument("org_id", help="Organization ID")
    p_add_dom.add_argument("domain", help="Domain to trust (e.g. acme.com)")
    p_add_dom.set_defaults(func=cmd_add_domain)

    # list-domains
    p_list_dom = subparsers.add_parser("list-domains", help="List trusted domains")
    p_list_dom.add_argument("org_id", help="Organization ID")
    p_list_dom.set_defaults(func=cmd_list_domains)

    parsed = parser.parse_args()
    parsed.func(parsed)


if __name__ == "__main__":
    main()
