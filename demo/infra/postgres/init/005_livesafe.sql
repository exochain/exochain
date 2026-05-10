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

-- LiveSafe.ai: Modern Civil Defense Preparedness + Golden Hour Response
-- Built on EXOCHAIN constitutional trust fabric

-- LiveSafe user profiles
CREATE TABLE IF NOT EXISTS livesafe_profiles (
    did TEXT PRIMARY KEY REFERENCES users(did),
    display_name TEXT,
    email TEXT,
    x25519_public_key_hex TEXT,
    preparedness_score INTEGER DEFAULT 0,
    onboarding_complete BOOLEAN DEFAULT FALSE,
    created_at_ms BIGINT NOT NULL
);

-- Emergency plans
CREATE TABLE IF NOT EXISTS emergency_plans (
    id TEXT PRIMARY KEY,
    owner_did TEXT NOT NULL,
    scenario_type TEXT NOT NULL,
    name TEXT NOT NULL,
    rally_point TEXT,
    go_bag_checklist JSONB DEFAULT '[]',
    communication_plan TEXT,
    evacuation_routes JSONB DEFAULT '[]',
    special_instructions TEXT,
    golden_hour_steps JSONB DEFAULT '[]',
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_plans_owner ON emergency_plans(owner_did);

-- ICE Cards (In Case of Emergency)
CREATE TABLE IF NOT EXISTS ice_cards (
    id TEXT PRIMARY KEY,
    owner_did TEXT NOT NULL,
    full_name TEXT NOT NULL,
    date_of_birth TEXT,
    blood_type TEXT,
    allergies JSONB DEFAULT '[]',
    medications JSONB DEFAULT '[]',
    medical_conditions JSONB DEFAULT '[]',
    emergency_contacts JSONB DEFAULT '[]',
    insurance_info TEXT,
    organ_donor BOOLEAN DEFAULT FALSE,
    dnr BOOLEAN DEFAULT FALSE,
    special_instructions TEXT,
    qr_token TEXT UNIQUE NOT NULL,
    card_status TEXT DEFAULT 'active'
        CHECK (card_status IN ('active','revoked','expired')),
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ice_owner ON ice_cards(owner_did);
CREATE INDEX IF NOT EXISTS idx_ice_qr ON ice_cards(qr_token);

-- ICE Card scan receipts (consent-gated access)
CREATE TABLE IF NOT EXISTS ice_scan_receipts (
    id TEXT PRIMARY KEY,
    card_id TEXT NOT NULL REFERENCES ice_cards(id),
    subscriber_did TEXT NOT NULL,
    responder_did TEXT NOT NULL,
    location TEXT,
    scanned_at_ms BIGINT NOT NULL,
    consent_expires_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_card ON ice_scan_receipts(card_id);

-- PACE trustee network (shared with VitalLock — same structure)
CREATE TABLE IF NOT EXISTS livesafe_pace_network (
    id BIGSERIAL PRIMARY KEY,
    owner_did TEXT NOT NULL,
    trustee_did TEXT,
    trustee_email TEXT NOT NULL,
    trustee_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('Primary','Alternate','Contingency','Emergency')),
    relationship TEXT,
    invitation_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (invitation_status IN ('pending','accepted','declined','expired')),
    shamir_share_encrypted TEXT,
    invitation_token TEXT UNIQUE,
    created_at_ms BIGINT NOT NULL,
    accepted_at_ms BIGINT,
    UNIQUE(owner_did, trustee_email)
);
CREATE INDEX IF NOT EXISTS idx_ls_pace_owner ON livesafe_pace_network(owner_did);
CREATE INDEX IF NOT EXISTS idx_ls_pace_trustee ON livesafe_pace_network(trustee_did);

-- Wellness checks
CREATE TABLE IF NOT EXISTS wellness_checks (
    id TEXT PRIMARY KEY,
    owner_did TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ok'
        CHECK (status IN ('ok','help','pending','expired')),
    responded_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wellness_owner ON wellness_checks(owner_did);

-- Golden hour protocol completions
CREATE TABLE IF NOT EXISTS golden_hour_runs (
    id TEXT PRIMARY KEY,
    owner_did TEXT NOT NULL,
    scenario_type TEXT NOT NULL,
    steps_completed INTEGER NOT NULL,
    total_steps INTEGER NOT NULL,
    duration_ms BIGINT,
    created_at_ms BIGINT NOT NULL
);
