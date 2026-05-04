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
