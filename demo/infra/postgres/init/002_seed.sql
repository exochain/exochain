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

-- ExoChain Demo Seed Data
-- 3 test users, constitution, delegations, sample decision, consent anchor

-- ── Users ──────────────────────────────────────────────────────────
INSERT INTO users (did, display_name, email, roles, tenant_id, created_at, status, pace_status, password_hash, salt, mfa_enabled) VALUES
  ('did:exo:alice', 'Alice Chen', 'alice@exochain.org', '["Chair","Governor"]', 'exochain-foundation', 1710806400000, 'Active', 'Enrolled', 'pbkdf2_placeholder_alice', 'salt_alice', true),
  ('did:exo:bob', 'Bob Martinez', 'bob@exochain.org', '["TechLead","Governor"]', 'exochain-foundation', 1710806400000, 'Active', 'Enrolled', 'pbkdf2_placeholder_bob', 'salt_bob', true),
  ('did:exo:carol', 'Carol Williams', 'carol@exochain.org', '["GeneralCounsel","Governor"]', 'exochain-foundation', 1710806400000, 'Active', 'Enrolled', 'pbkdf2_placeholder_carol', 'salt_carol', true)
ON CONFLICT DO NOTHING;

-- ── Identity Scores ────────────────────────────────────────────────
INSERT INTO identity_scores (did, score, tier, factors, last_updated) VALUES
  ('did:exo:alice', 95, 'Platinum', '{"kyc": true, "mfa": true, "tenure_months": 24, "governance_participation": 0.92}', 1710806400000),
  ('did:exo:bob', 88, 'Gold', '{"kyc": true, "mfa": true, "tenure_months": 18, "governance_participation": 0.85}', 1710806400000),
  ('did:exo:carol', 91, 'Platinum', '{"kyc": true, "mfa": true, "tenure_months": 20, "governance_participation": 0.88}', 1710806400000)
ON CONFLICT DO NOTHING;

-- ── Constitution v1.0.0 ────────────────────────────────────────────
INSERT INTO constitutions (tenant_id, version, payload) VALUES
  ('exochain-foundation', '1.0.0', '{
    "name": "ExoChain Foundation Constitution",
    "version": "1.0.0",
    "invariants": [
      "DemocraticLegitimacy",
      "DelegationGovernance",
      "DualControl",
      "HumanOversight",
      "TransparencyAccountability",
      "ConflictAdjudication",
      "TechnologicalHumility",
      "ExistentialSafeguard"
    ],
    "quorum": {
      "default_threshold": 0.51,
      "constitutional_threshold": 0.67,
      "emergency_threshold": 0.75,
      "min_independent": 2
    },
    "decision_classes": ["Operational", "Strategic", "Constitutional", "Emergency"],
    "adopted_at_ms": 1710806400000
  }')
ON CONFLICT DO NOTHING;

-- ── Delegations ────────────────────────────────────────────────────
INSERT INTO delegations (id_hash, tenant_id, delegator, delegatee, created_at_ms, expires_at, constitution_version, payload) VALUES
  ('delegation-alice-bob-001', 'exochain-foundation', 'did:exo:alice', 'did:exo:bob', 1710806400000, 1742342400000, '1.0.0', '{
    "scope": ["Operational"],
    "permissions": ["CreateDecision", "Vote", "SubmitEvidence"],
    "signature": "placeholder_sig"
  }')
ON CONFLICT DO NOTHING;

-- ── Sample Decision (in Deliberation) ──────────────────────────────
INSERT INTO decisions (id_hash, tenant_id, status, title, decision_class, author, created_at_ms, constitution_version, payload) VALUES
  ('decision-budget-2026-q1', 'exochain-foundation', 'Deliberated', 'Q1 2026 Operating Budget Approval', 'Operational', 'did:exo:alice', 1710806400000, '1.0.0', '{
    "description": "Approve the Q1 2026 operating budget of $2.4M covering infrastructure, staffing, and compliance costs.",
    "votes": [],
    "evidence": [],
    "quorum_spec": {"threshold": 0.51, "min_independent": 2}
  }')
ON CONFLICT DO NOTHING;

-- ── Consent Anchor ─────────────────────────────────────────────────
INSERT INTO consent_anchors (consent_id, subscriber_did, provider_did, scope, granted_at_ms, expires_at_ms, audit_receipt_hash) VALUES
  ('consent-cybermedica-001', 'did:exo:alice', 'did:exo:cybermedica', '["health_data_read", "emergency_contact"]', 1710806400000, 1742342400000, '0000000000000000000000000000000000000000000000000000000000000000')
ON CONFLICT DO NOTHING;

-- ── Genesis Audit Entry ────────────────────────────────────────────
INSERT INTO audit_entries (sequence, prev_hash, event_hash, event_type, actor, tenant_id, timestamp_physical_ms, timestamp_logical, entry_hash) VALUES
  (0, '0000000000000000000000000000000000000000000000000000000000000000', 'genesis', 'SystemGenesis', 'did:exo:system', 'exochain-foundation', 1710806400000, 0, '0000000000000000000000000000000000000000000000000000000000000001')
ON CONFLICT DO NOTHING;

-- ── Enrollment Log ─────────────────────────────────────────────────
INSERT INTO enrollment_log (did, entity_type, step, timestamp, verified_by, audit_hash) VALUES
  ('did:exo:alice', 'Human', 'IdentityVerified', 1710806400000, 'did:exo:system', 'enrollment_alice_hash'),
  ('did:exo:bob', 'Human', 'IdentityVerified', 1710806400000, 'did:exo:system', 'enrollment_bob_hash'),
  ('did:exo:carol', 'Human', 'IdentityVerified', 1710806400000, 'did:exo:system', 'enrollment_carol_hash');
