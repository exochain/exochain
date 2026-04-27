-- EXOCHAIN decision.forum persistence layer
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users
CREATE TABLE IF NOT EXISTS users (
    did TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    roles JSONB NOT NULL DEFAULT '[]',
    tenant_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    pace_status TEXT NOT NULL DEFAULT 'Unenrolled',
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Agents
CREATE TABLE IF NOT EXISTS agents (
    did TEXT PRIMARY KEY,
    agent_name TEXT NOT NULL,
    agent_type TEXT NOT NULL,
    owner_did TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    capabilities JSONB NOT NULL DEFAULT '[]',
    trust_tier TEXT NOT NULL DEFAULT 'Untrusted',
    trust_score INTEGER NOT NULL DEFAULT 0,
    delegation_id TEXT,
    pace_status TEXT NOT NULL DEFAULT 'Unenrolled',
    created_at BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    max_decision_class TEXT NOT NULL
);

-- Decisions (JSONB payload for complex nested governance objects)
CREATE TABLE IF NOT EXISTS decisions (
    id_hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    status TEXT NOT NULL,
    title TEXT NOT NULL,
    decision_class TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    constitution_version TEXT NOT NULL,
    payload JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_status ON decisions(status);

-- Delegations (JSONB payload for scope/signature)
CREATE TABLE IF NOT EXISTS delegations (
    id_hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    delegator TEXT NOT NULL,
    delegatee TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT,
    constitution_version TEXT NOT NULL,
    payload JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_delegations_delegator ON delegations(delegator);
CREATE INDEX IF NOT EXISTS idx_delegations_delegatee ON delegations(delegatee);

-- Audit entries (full relational for chain verification)
CREATE TABLE IF NOT EXISTS audit_entries (
    sequence BIGINT PRIMARY KEY,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    timestamp_physical_ms BIGINT NOT NULL,
    timestamp_logical INTEGER NOT NULL DEFAULT 0,
    entry_hash TEXT NOT NULL
);

-- Constitution (versioned, single active per tenant)
CREATE TABLE IF NOT EXISTS constitutions (
    tenant_id TEXT NOT NULL,
    version TEXT NOT NULL,
    payload JSONB NOT NULL,
    PRIMARY KEY (tenant_id, version)
);

-- Identity scores
CREATE TABLE IF NOT EXISTS identity_scores (
    did TEXT PRIMARY KEY,
    score INTEGER NOT NULL,
    tier TEXT NOT NULL,
    factors JSONB NOT NULL,
    last_updated BIGINT NOT NULL
);

-- Enrollment log
CREATE TABLE IF NOT EXISTS enrollment_log (
    id BIGSERIAL PRIMARY KEY,
    did TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    step TEXT NOT NULL,
    timestamp BIGINT NOT NULL,
    verified_by TEXT NOT NULL,
    audit_hash TEXT NOT NULL
);

-- HLC counter (singleton)
CREATE TABLE IF NOT EXISTS hlc_state (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    counter BIGINT NOT NULL DEFAULT 1000
);
INSERT INTO hlc_state (counter) VALUES (1000) ON CONFLICT DO NOTHING;

-- LiveSafe tables
CREATE TABLE IF NOT EXISTS livesafe_identities (
    did TEXT PRIMARY KEY,
    odentity_composite_basis_points INTEGER NOT NULL DEFAULT 0,
    pace_status TEXT NOT NULL DEFAULT 'Incomplete',
    card_status TEXT NOT NULL DEFAULT 'NotIssued',
    created_at_ms BIGINT NOT NULL,
    exochain_anchor TEXT
);

CREATE TABLE IF NOT EXISTS scan_receipts (
    scan_id TEXT PRIMARY KEY,
    subscriber_did TEXT NOT NULL,
    responder_did TEXT NOT NULL,
    location TEXT,
    scanned_at_ms BIGINT NOT NULL,
    consent_expires_at_ms BIGINT NOT NULL,
    audit_receipt_hash TEXT NOT NULL,
    anchor_receipt TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_subscriber ON scan_receipts(subscriber_did);

CREATE TABLE IF NOT EXISTS consent_anchors (
    consent_id TEXT PRIMARY KEY,
    subscriber_did TEXT NOT NULL,
    provider_did TEXT NOT NULL,
    scope JSONB NOT NULL DEFAULT '[]',
    granted_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT,
    revoked_at_ms BIGINT,
    audit_receipt_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_consent_subscriber ON consent_anchors(subscriber_did);

CREATE TABLE IF NOT EXISTS trustee_shard_status (
    id BIGSERIAL PRIMARY KEY,
    subscriber_did TEXT NOT NULL,
    trustee_did TEXT NOT NULL,
    role TEXT NOT NULL,
    shard_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    accepted_at_ms BIGINT
);
CREATE INDEX IF NOT EXISTS idx_shard_subscriber ON trustee_shard_status(subscriber_did);
