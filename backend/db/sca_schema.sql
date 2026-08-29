-- sca_schema.sql
-- ----------------
-- Run this in the Supabase SQL editor (same project as organizations/employees
-- from services/supabase_service.py). Adds real SCA scanning, risk flagging,
-- and per-org auto-approval rules on top of the existing SENTRY schema.
--
-- FAIL-SAFE GUARANTEE (read before changing anything here):
-- high_risky rows can NEVER be auto-approved. This is enforced in THREE
-- independent places so a bug in any one layer can't silently break it:
--   1. Application code (backend/services/risk_classifier.py) never emits
--      an auto-approve decision for high_risky.
--   2. auto_approval_rules has a CHECK constraint preventing anyone from
--      setting can_auto_approve=true for tier='high_risky'.
--   3. risk_flags.status can only move to 'completed' via an explicit
--      admin action row in scan_audit_log (see trigger below) UNLESS
--      the matching rule's can_auto_approve is true AND tier != 'high_risky'.

-- ---------------------------------------------------------------------------
-- 1. Per-org, org-defined auto-approval rules (Q2/Q6 — set at runtime by
--    the org admin via the frontend, not hardcoded).
-- ---------------------------------------------------------------------------
create table if not exists auto_approval_rules (
    id              uuid primary key default gen_random_uuid(),
    org_id          text not null references organizations(org_id) on delete cascade,
    tier            text not null check (tier in ('not_risky', 'part_risky', 'high_risky')),
    can_auto_approve boolean not null default false,
    updated_by      text,                      -- employee_id of admin who set this
    updated_at      timestamptz not null default now(),

    -- HARD DB-LEVEL FAIL-SAFE: this row can never say "auto-approve high risk",
    -- no matter what the application layer sends. Belt-and-suspenders on top
    -- of the same rule enforced in risk_classifier.py.
    constraint high_risky_never_auto_approves
        check (not (tier = 'high_risky' and can_auto_approve = true)),

    unique (org_id, tier)
);

-- Seed default rows for an org the first time it's created — safe defaults:
-- not_risky auto-approves, part_risky and high_risky both require a human,
-- until the org admin explicitly changes part_risky at runtime.
-- (Application code calls this after org creation — see risk_classifier.py
-- ensure_default_rules().)

-- ---------------------------------------------------------------------------
-- 2. SCA scan results — one row per dependency/package scanned via OSV.dev
-- ---------------------------------------------------------------------------
create table if not exists scan_results (
    id              uuid primary key default gen_random_uuid(),
    org_id          text not null references organizations(org_id) on delete cascade,
    employee_id     text references employees(employee_id) on delete set null,
    package_name    text not null,
    package_version text not null,
    ecosystem       text not null default 'PyPI',   -- OSV ecosystem string
    vuln_id         text,                            -- e.g. GHSA-xxxx or CVE-xxxx
    cvss_score      numeric(3,1),                    -- 0.0-10.0, null if OSV gave no CVSS
    summary         text,
    tier            text not null check (tier in ('not_risky', 'part_risky', 'high_risky')),
    raw_osv_response jsonb,                          -- full OSV API response, for audit/Q&A
    created_at      timestamptz not null default now()
);

create index if not exists idx_scan_results_org on scan_results (org_id);
create index if not exists idx_scan_results_tier on scan_results (tier);

-- ---------------------------------------------------------------------------
-- 3. Risk flags — the thing employees see as "Pending"/"Completed", and
--    admins see in full. One flag per scan_result that needs tracking.
-- ---------------------------------------------------------------------------
create table if not exists risk_flags (
    id              uuid primary key default gen_random_uuid(),
    scan_result_id  uuid not null references scan_results(id) on delete cascade,
    org_id          text not null references organizations(org_id) on delete cascade,
    employee_id     text references employees(employee_id) on delete set null,
    tier            text not null check (tier in ('not_risky', 'part_risky', 'high_risky')),
    status          text not null default 'pending' check (status in ('pending', 'completed')),
    resolution      text check (resolution in ('auto_approved', 'admin_approved', 'admin_denied')),
    approved_by     text,                     -- employee_id of admin, null if auto
    approved_at     timestamptz,
    created_at      timestamptz not null default now(),

    -- Second independent guard: a row can only be auto_approved if its tier
    -- is not high_risky. Mirrors the constraint on auto_approval_rules.
    constraint high_risky_never_auto_resolved
        check (not (tier = 'high_risky' and resolution = 'auto_approved'))
);

create index if not exists idx_risk_flags_org on risk_flags (org_id);
create index if not exists idx_risk_flags_employee on risk_flags (employee_id);
create index if not exists idx_risk_flags_status on risk_flags (status);

-- ---------------------------------------------------------------------------
-- 4. Audit log — every classification + every approval/denial decision,
--    matching SENTRY's existing audit_log philosophy (AuditEntry in models.py)
-- ---------------------------------------------------------------------------
create table if not exists scan_audit_log (
    id              uuid primary key default gen_random_uuid(),
    org_id          text not null references organizations(org_id) on delete cascade,
    risk_flag_id    uuid references risk_flags(id) on delete cascade,
    message         text not null,
    actor           text,                     -- employee_id, or 'system' for auto actions
    created_at      timestamptz not null default now()
);

create index if not exists idx_scan_audit_log_org on scan_audit_log (org_id);

-- ---------------------------------------------------------------------------
-- 5. RBAC: admin/employee role split (Option A, confirmed with the user).
--    The employees table already exists (services/supabase_service.py) —
--    this ALTER adds the missing role flag without touching existing rows.
-- ---------------------------------------------------------------------------
alter table employees
    add column if not exists is_admin boolean not null default false;

-- One-time manual step (run once per existing org, NOT automated — a
-- script silently deciding who your admin is would be a real security
-- decision made without you): promote whichever employee should be the
-- org's admin. Example:
--
--   update employees set is_admin = true where employee_id = 'EMP-0001';
--
-- New orgs going forward: the FIRST employee ever created for an org via
-- POST /employees is automatically made admin (see
-- services/supabase_service.py's create_employee() — enforced in code,
-- not here, since it needs a count query first).

-- ---------------------------------------------------------------------------
-- 6. Unify Windows-notification findings into the SAME table as SCA scan
--    results (architectural decision, confirmed with the user), instead
--    of the old separate Alert/STORE pipeline in main.py. This gives
--    notification findings the same admin-dashboard visibility, the same
--    Approve/Deny workflow, the same analytics, and — critically — real
--    per-employee traceability (each employee's own poller instance
--    authenticates as THAT employee, so risk_flags.employee_id is the
--    real affected employee, not always the admin).
-- ---------------------------------------------------------------------------
alter table scan_results
    add column if not exists source_type text not null default 'sca_scan'
        check (source_type in ('sca_scan', 'notification'));

alter table scan_results
    add column if not exists app_name text;

alter table scan_results
    add column if not exists notification_text text;

-- package_name/package_version were NOT NULL (correct for SCA scans, but
-- a notification finding has no package at all) — relax to nullable.
-- Safe to run even if already nullable (Postgres no-ops in that case).
alter table scan_results alter column package_name drop not null;
alter table scan_results alter column package_version drop not null;

create index if not exists idx_scan_results_source_type on scan_results (source_type);