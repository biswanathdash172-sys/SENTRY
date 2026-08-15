-- schema.sql
-- ----------
-- Raw SQL reference schema for SENTRY, matching ARCHITECTURE.md §5 and the
-- Pydantic shapes in models.py. This file is NOT auto-run by the app —
-- database.py creates the actual table via SQLAlchemy's create_all(), which
-- is simpler and safer for a hackathon (works identically on SQLite for
-- local testing and Postgres in production, no migration tool needed).
--
-- Keep this file as the human-readable reference / for manual `psql` setup
-- if the team wants to inspect or seed the DB directly.

CREATE TABLE IF NOT EXISTS alerts (
    id          VARCHAR(64) PRIMARY KEY,
    title       TEXT NOT NULL,
    severity    VARCHAR(16) NOT NULL,       -- low | medium | high | critical
    status      VARCHAR(16) NOT NULL,       -- open | resolved
    created_at  TIMESTAMP NOT NULL,
    -- Evidence, attack_chain, playbook, and audit_log are stored as a
    -- single JSON blob per alert (see db/database.py docstring for why:
    -- this keeps the hackathon schema a single drop-in table instead of
    -- five joined tables, while still matching the Alert shape in
    -- models.py exactly on read).
    data        JSON NOT NULL
);

-- Reference-only breakdown of what lives inside `data` (matches
-- ARCHITECTURE.md §5's original multi-table plan, kept as one JSON
-- column per alert here for hackathon simplicity):
--   evidence         -> list of {id, source_type, description, confidence, timestamp}
--   attack_chain     -> list of plain-English strings
--   playbook         -> list of {id, label, risk_level, mode}
--   audit_log        -> list of {id, timestamp, message}
--
-- Full normalized version (credentials, separate evidence/playbook_action/
-- audit_log tables) is the documented future upgrade path if the project
-- continues past the hackathon — not required for the demo.

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);