-- Link vote audit entries back to their decision for /api/v1/audit/:decision_id.
ALTER TABLE audit_entries
    ADD COLUMN IF NOT EXISTS decision_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_audit_entries_decision_id
    ON audit_entries(decision_id);
