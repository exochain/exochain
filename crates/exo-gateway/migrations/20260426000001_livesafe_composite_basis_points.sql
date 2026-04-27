-- Replace unaudited LiveSafe floating composite scores with deterministic
-- integer basis-points storage. Existing floating scores had no audited
-- semantics in the gateway and are not preserved.
ALTER TABLE livesafe_identities
    ADD COLUMN IF NOT EXISTS odentity_composite_basis_points INTEGER NOT NULL DEFAULT 0;

ALTER TABLE livesafe_identities
    DROP COLUMN IF EXISTS odentity_composite;
