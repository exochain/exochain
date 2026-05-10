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

-- Adjudication resolver tables (APE-53)
--
-- These tables back the production path of `build_adjudication_context_from_db`
-- in exo-gateway.  The dev/test scaffold (WO-009 deny-all) continues to operate
-- independently; these tables are only queried when the `production-db` Cargo
-- feature is enabled.

-- Active roles held by each agent DID.
-- `branch` encodes the constitutional branch: 'executive' | 'legislative' | 'judicial'.
-- `valid_from` and `expires_at` are epoch-millisecond timestamps (INT8).
CREATE TABLE IF NOT EXISTS agent_roles (
    agent_did   TEXT    NOT NULL,
    role        TEXT    NOT NULL,
    branch      TEXT    NOT NULL DEFAULT 'executive',
    granted_by  TEXT    NOT NULL,
    valid_from  BIGINT  NOT NULL,
    expires_at  BIGINT,
    PRIMARY KEY (agent_did, role)
);

CREATE INDEX IF NOT EXISTS idx_agent_roles_agent_did ON agent_roles(agent_did);

-- Consent records linking a subject (bailor) to an actor (bailee).
-- `bailment_type` is a human-readable label (e.g. 'standard', 'emergency').
-- `status` is 'active' | 'revoked' | 'expired'.
CREATE TABLE IF NOT EXISTS consent_records (
    subject_did   TEXT    NOT NULL,
    actor_did     TEXT    NOT NULL,
    scope         TEXT    NOT NULL,
    bailment_type TEXT    NOT NULL DEFAULT 'standard',
    status        TEXT    NOT NULL DEFAULT 'active',
    created_at    BIGINT  NOT NULL,
    expires_at    BIGINT,
    PRIMARY KEY (subject_did, actor_did, scope)
);

CREATE INDEX IF NOT EXISTS idx_consent_records_actor ON consent_records(actor_did, status);
CREATE INDEX IF NOT EXISTS idx_consent_records_subject ON consent_records(subject_did);

-- Serialised `AuthorityChain` blobs keyed by the terminal actor DID.
-- `chain_json` is the JSONB-encoded `exo_gatekeeper::types::AuthorityChain`.
-- Multiple rows per actor are allowed; queries select the most-recent valid one.
CREATE TABLE IF NOT EXISTS authority_chains (
    actor_did   TEXT    NOT NULL,
    chain_json  JSONB   NOT NULL,
    valid_from  BIGINT  NOT NULL,
    expires_at  BIGINT,
    PRIMARY KEY (actor_did, valid_from)
);

CREATE INDEX IF NOT EXISTS idx_authority_chains_actor ON authority_chains(actor_did);
