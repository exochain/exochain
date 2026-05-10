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

-- Durable DID registry backing for DB-configured gateway identity routes.
--
-- LocalDidRegistry remains a bounded development/cache implementation. When
-- DATABASE_URL is configured, REST identity registration and resolution use
-- this table so DID documents survive process restarts.
CREATE TABLE IF NOT EXISTS did_documents (
    did TEXT PRIMARY KEY,
    document JSONB NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_did_documents_active_did
    ON did_documents(did)
    WHERE revoked = false;
