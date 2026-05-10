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

-- Conflict-of-interest declarations backing vote recusal checks.
--
-- Vote handling must fail closed if this register cannot be read. The JSONB
-- payload stores the canonical `exo_governance::conflict::ConflictDeclaration`
-- shape while indexed scalar columns keep the lookup deterministic.
CREATE TABLE IF NOT EXISTS conflict_declarations (
    id_hash TEXT PRIMARY KEY,
    declarant_did TEXT NOT NULL,
    nature TEXT NOT NULL,
    related_dids JSONB NOT NULL,
    timestamp_physical_ms BIGINT NOT NULL CHECK (timestamp_physical_ms > 0),
    timestamp_logical INTEGER NOT NULL DEFAULT 0 CHECK (timestamp_logical >= 0),
    payload JSONB NOT NULL,
    CHECK (length(trim(nature)) > 0),
    CHECK (jsonb_typeof(related_dids) = 'array'),
    CHECK (jsonb_array_length(related_dids) > 0)
);

CREATE INDEX IF NOT EXISTS idx_conflict_declarations_declarant
    ON conflict_declarations(declarant_did);
