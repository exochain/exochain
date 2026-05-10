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

-- EXOCHAIN-REM-009: Governance health monitoring schema
-- Non-destructive additive migration

-- Governance health snapshots (one row per monitoring run)
CREATE TABLE IF NOT EXISTS governance_health_snapshots (
    run_id          TEXT PRIMARY KEY,           -- UUID from monitoring workflow
    commit_sha      TEXT NOT NULL,              -- HEAD commit at scan time
    scanned_at_ms   BIGINT NOT NULL,            -- Physical wall-clock ms
    invariant_coverage  TEXT NOT NULL,          -- "0-100%"
    tnc_coverage        TEXT NOT NULL,          -- "0-100%"
    bcts_integrity      TEXT NOT NULL,          -- "pass" | "fail"
    governance_score    TEXT NOT NULL,          -- "A" | "B" | "C" | "D" | "F"
    findings_digest TEXT NOT NULL,              -- Blake3 hash of the findings JSON
    findings_count_critical INTEGER NOT NULL DEFAULT 0,
    findings_count_high     INTEGER NOT NULL DEFAULT 0,
    findings_count_medium   INTEGER NOT NULL DEFAULT 0,
    findings_count_low      INTEGER NOT NULL DEFAULT 0,
    -- Signed attestation envelope (Ed25519, base64url)
    attestation_signature   TEXT,
    attestation_signer_did  TEXT,
    -- CR-001 §8 work order status (JSON object keyed by work order id)
    cr001_work_orders       JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_gov_health_scanned ON governance_health_snapshots(scanned_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_gov_health_score ON governance_health_snapshots(governance_score);

-- Individual findings per run (linked to snapshots)
CREATE TABLE IF NOT EXISTS governance_findings (
    id              BIGSERIAL PRIMARY KEY,
    run_id          TEXT NOT NULL REFERENCES governance_health_snapshots(run_id) ON DELETE CASCADE,
    finding_id      TEXT NOT NULL,              -- e.g. "CG-001"
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,              -- constitutional-drift|invariant-degradation|governance-gap|compliance-risk|architecture-debt
    severity        TEXT NOT NULL,              -- Critical|High|Medium|Low
    file_path       TEXT,
    line_number     TEXT,
    description     TEXT NOT NULL,
    remediation     TEXT NOT NULL,
    invariants_affected JSONB NOT NULL DEFAULT '[]',
    scanned_at_ms   BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gov_findings_run ON governance_findings(run_id);
CREATE INDEX IF NOT EXISTS idx_gov_findings_severity ON governance_findings(severity);

-- Human approval gates for self-improvement cycle triggers
-- A finding that qualifies for auto-trigger must have an approval record
-- before the self-improvement cycle may begin implementation.
CREATE TABLE IF NOT EXISTS governance_trigger_approvals (
    approval_id     TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL REFERENCES governance_health_snapshots(run_id),
    requested_at_ms BIGINT NOT NULL,
    approved_at_ms  BIGINT,
    approved_by_did TEXT,                       -- must be a human DID (SignerType 0x01)
    status          TEXT NOT NULL DEFAULT 'Pending', -- Pending|Approved|Rejected
    notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_trigger_approvals_status ON governance_trigger_approvals(status);
