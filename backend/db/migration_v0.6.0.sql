-- ============================================================
-- SENTRY v0.6.0 — Supabase Schema Migration
-- Run this in the Supabase Dashboard → SQL Editor
-- https://supabase.com/dashboard/project/bewhtkfzsgxkvdnuelxg/sql
-- ============================================================

-- 1. Add Cyber Head role to employees
ALTER TABLE employees
    ADD COLUMN IF NOT EXISTS is_cyber_head boolean NOT NULL DEFAULT false;

-- 2. Trusted sender domain whitelist (per-org)
CREATE TABLE IF NOT EXISTS domain_whitelist (
    id          uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id      text REFERENCES organizations(org_id) NOT NULL,
    domain      text NOT NULL,
    added_by    text,
    added_at    timestamptz DEFAULT now(),
    UNIQUE(org_id, domain)
);

-- 3. Device freeze requests
CREATE TABLE IF NOT EXISTS device_freeze_requests (
    id              uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id          text REFERENCES organizations(org_id) NOT NULL,
    employee_id     text NOT NULL,
    reason          text,
    status          text NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'active', 'lifted')),
    triggered_by    text,
    triggered_at    timestamptz DEFAULT now(),
    lifted_by       text,
    lifted_at       timestamptz,
    risk_flag_id    uuid
);

-- 4. Enable Row Level Security (optional but recommended)
-- ALTER TABLE domain_whitelist ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE device_freeze_requests ENABLE ROW LEVEL SECURITY;

-- 5. Grant service role access (needed if using service_role key, which SENTRY does)
GRANT ALL ON domain_whitelist TO service_role;
GRANT ALL ON device_freeze_requests TO service_role;
GRANT ALL ON employees TO service_role;

-- Verification: run these SELECTs to confirm
-- SELECT column_name FROM information_schema.columns WHERE table_name = 'employees' AND column_name = 'is_cyber_head';
-- SELECT table_name FROM information_schema.tables WHERE table_name IN ('domain_whitelist', 'device_freeze_requests');
