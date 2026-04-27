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
