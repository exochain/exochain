-- Indexes for gateway runtime list, tenant-filter, and audit activity queries.
CREATE INDEX IF NOT EXISTS idx_users_created_at
    ON users(created_at);

CREATE INDEX IF NOT EXISTS idx_agents_tenant_created_at
    ON agents(tenant_id, created_at);

CREATE INDEX IF NOT EXISTS idx_agents_created_at
    ON agents(created_at);

CREATE INDEX IF NOT EXISTS idx_decisions_tenant_created_at_ms
    ON decisions(tenant_id, created_at_ms);

CREATE INDEX IF NOT EXISTS idx_decisions_created_at_ms
    ON decisions(created_at_ms);

CREATE INDEX IF NOT EXISTS idx_delegations_created_at_ms
    ON delegations(created_at_ms);

CREATE INDEX IF NOT EXISTS idx_delegations_active_delegatee
    ON delegations(delegatee)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_delegations_active_delegator
    ON delegations(delegator)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_audit_entries_actor_event_type
    ON audit_entries(actor, event_type);
