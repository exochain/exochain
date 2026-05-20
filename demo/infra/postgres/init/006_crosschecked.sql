-- Copyright 2026 Exochain Foundation
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at:
--
--     https://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- SPDX-License-Identifier: Apache-2.0

-- CrossChecked.ai: Plural Intelligence Verification Platform
-- Powered by EXOCHAIN Constitutional Trust Fabric
-- Production schema — full parity with sybil-cli + 5-panel AI-IRB council

-- Crosscheck policy configuration
CREATE TABLE IF NOT EXISTS crosscheck_policy (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'quorum'
        CHECK (mode IN ('single', 'quorum')),
    quorum_count INTEGER NOT NULL DEFAULT 2,
    allowed_roles JSONB DEFAULT '["reviewer", "steward"]',
    require_valid_signatures BOOLEAN DEFAULT TRUE,
    reject_veto BOOLEAN DEFAULT TRUE,
    created_at_ms BIGINT NOT NULL
);

-- Default clearance policy (matching upk.yaml)
INSERT INTO crosscheck_policy (id, name, mode, quorum_count, allowed_roles, require_valid_signatures, reject_veto, created_at_ms)
VALUES ('default', 'Default Clearance Policy', 'quorum', 2, '["reviewer", "steward"]', true, true, 0)
ON CONFLICT (id) DO NOTHING;

-- Public key registry for actors
CREATE TABLE IF NOT EXISTS crosscheck_keys (
    actor_did TEXT PRIMARY KEY,
    public_key_b64 TEXT NOT NULL,
    registered_at_ms BIGINT NOT NULL
);

-- Crosscheck proposals (= DecisionRecord in sybil-cli)
CREATE TABLE IF NOT EXISTS crosscheck_proposals (
    id TEXT PRIMARY KEY,
    author_did TEXT NOT NULL,
    title TEXT NOT NULL,
    context TEXT NOT NULL,
    decision TEXT,
    consequences TEXT,
    method TEXT NOT NULL DEFAULT 'mosaic'
        CHECK (method IN ('mosaic', 'adversarial', 'redteam', 'debate', 'jury')),
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'submitted', 'crosschecking', 'verified', 'anchored', 'deliberating', 'ratified', 'rejected')),
    decision_class TEXT DEFAULT 'Operational'
        CHECK (decision_class IN ('Operational', 'Procedural', 'Strategic', 'Constitutional')),
    full_5x5 BOOLEAN DEFAULT FALSE,
    assumptions JSONB DEFAULT '[]',
    options_considered JSONB DEFAULT '[]',
    tags JSONB DEFAULT '[]',
    record_hash TEXT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_xc_proposals_status ON crosscheck_proposals(status);
CREATE INDEX IF NOT EXISTS idx_xc_proposals_author ON crosscheck_proposals(author_did);

-- Evidence items attached to proposals
CREATE TABLE IF NOT EXISTS crosscheck_evidence (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES crosscheck_proposals(id),
    kind TEXT NOT NULL DEFAULT 'link',
    description TEXT NOT NULL,
    uri TEXT,
    content_hash TEXT,
    metadata JSONB DEFAULT '{}',
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_xc_evidence_proposal ON crosscheck_evidence(proposal_id);

-- Individual crosscheck opinions (one per agent per proposal)
CREATE TABLE IF NOT EXISTS crosscheck_opinions (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES crosscheck_proposals(id),
    agent_did TEXT NOT NULL,
    agent_kind TEXT NOT NULL DEFAULT 'ai'
        CHECK (agent_kind IN ('ai', 'human', 'hybrid', 'unknown')),
    agent_label TEXT,
    model TEXT,
    policy_id TEXT,
    stance TEXT NOT NULL
        CHECK (stance IN ('support', 'oppose', 'amend', 'abstain')),
    summary TEXT NOT NULL,
    rationale TEXT,
    confidence DOUBLE PRECISION CHECK (confidence >= 0.0 AND confidence <= 1.0),
    risks JSONB DEFAULT '[]',
    suggested_edits TEXT,
    evidence_refs JSONB DEFAULT '[]',
    panel TEXT CHECK (panel IN ('Governance', 'Legal', 'Architecture', 'Security', 'Operations')),
    property TEXT CHECK (property IN ('Storable', 'Diffable', 'Transferable', 'Auditable', 'Contestable')),
    submitted_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_xc_opinions_proposal ON crosscheck_opinions(proposal_id);
CREATE INDEX IF NOT EXISTS idx_xc_opinions_panel ON crosscheck_opinions(panel);

-- Synthesized crosscheck reports
CREATE TABLE IF NOT EXISTS crosscheck_reports (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES crosscheck_proposals(id),
    schema_version TEXT DEFAULT '0.2',
    created_by TEXT,
    question TEXT,
    method TEXT,
    synthesis TEXT,
    dissent TEXT,
    dissenters JSONB DEFAULT '[]',
    independence_result JSONB,
    coordination_signals JSONB DEFAULT '[]',
    report_hash TEXT,
    metadata JSONB DEFAULT '{}',
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_xc_reports_proposal ON crosscheck_reports(proposal_id);

-- EXOCHAIN anchor receipts
CREATE TABLE IF NOT EXISTS crosscheck_anchors (
    id TEXT PRIMARY KEY,
    report_id TEXT NOT NULL REFERENCES crosscheck_reports(id),
    proposal_id TEXT NOT NULL REFERENCES crosscheck_proposals(id),
    chain TEXT DEFAULT 'exochain',
    record_hash TEXT NOT NULL,
    txid TEXT,
    audit_entry_sequence BIGINT,
    metadata JSONB DEFAULT '{}',
    anchored_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_xc_anchors_report ON crosscheck_anchors(report_id);

-- Council deliberations (voting sessions)
CREATE TABLE IF NOT EXISTS crosscheck_deliberations (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES crosscheck_proposals(id),
    report_id TEXT REFERENCES crosscheck_reports(id),
    deliberation_json JSONB NOT NULL,
    quorum_policy JSONB NOT NULL,
    participants JSONB DEFAULT '[]',
    result TEXT CHECK (result IN ('Approved', 'Rejected', 'NoQuorum')),
    votes_for INTEGER DEFAULT 0,
    votes_against INTEGER DEFAULT 0,
    abstentions INTEGER DEFAULT 0,
    opened_at_ms BIGINT NOT NULL,
    closed_at_ms BIGINT
);
CREATE INDEX IF NOT EXISTS idx_xc_deliberations_proposal ON crosscheck_deliberations(proposal_id);

-- Custody events (tamper-evident chain of custody)
CREATE TABLE IF NOT EXISTS crosscheck_custody_events (
    id BIGSERIAL PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES crosscheck_proposals(id),
    actor_did TEXT NOT NULL,
    role TEXT DEFAULT 'participant'
        CHECK (role IN ('proposer', 'reviewer', 'steward', 'participant')),
    action TEXT NOT NULL,
    attestation TEXT CHECK (attestation IN ('approve', 'reject', 'abstain', 'amend')),
    record_hash TEXT,
    signature TEXT,
    public_key_b64 TEXT,
    notes TEXT,
    metadata JSONB DEFAULT '{}',
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_xc_custody_proposal ON crosscheck_custody_events(proposal_id);

-- Clearance certificates
CREATE TABLE IF NOT EXISTS crosscheck_clearance_certs (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES crosscheck_proposals(id),
    policy_id TEXT REFERENCES crosscheck_policy(id),
    approvals JSONB DEFAULT '[]',
    rejections JSONB DEFAULT '[]',
    abstentions JSONB DEFAULT '[]',
    quorum_met BOOLEAN NOT NULL,
    policy_snapshot JSONB NOT NULL,
    issued_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_xc_clearance_proposal ON crosscheck_clearance_certs(proposal_id);
