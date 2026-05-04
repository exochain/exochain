ALTER TABLE did_documents
    ADD COLUMN IF NOT EXISTS erased_at_ms BIGINT;

CREATE INDEX IF NOT EXISTS idx_did_documents_erased_at_ms
    ON did_documents(erased_at_ms)
    WHERE erased_at_ms IS NOT NULL;
