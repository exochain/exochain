# Gauntlet F-151 MMR Proof Validation

Date: 2026-05-15

## Classification

- Finding: F-151, `mmr prove() returns empty proof on invalid position`.
- Report source: imported evidence from `Exochain Gauntlet Findings`.
- Owned path reviewed: `crates/exo-dag/src/mmr.rs`.
- Path classification: EXOCHAIN core.

## Current-Main Disposition

The finding is stale in current `main`. `prove()` rejects out-of-range positions
before constructing an `MmrProof` and returns `DagError::MmrPositionOutOfBounds`
with the requested position and the current leaf count.

The verifier also fails closed when a valid proof for an in-range leaf is replayed
with an out-of-range position for the proof's recorded leaf set.

## Verification Evidence

Commands run from `/Users/bobstewart/dev/exochain`:

```bash
cargo test -p exo-dag mmr::tests::proof_out_of_bounds -- --nocapture
cargo test -p exo-dag mmr::tests::proof_for_real_leaf_fails_out_of_bounds_position -- --nocapture
```

Both commands passed on current `main`.

## Source Evidence

- `crates/exo-dag/src/mmr.rs`: `prove()` checks
  `position >= mmr.leaves.len()` and returns `DagError::MmrPositionOutOfBounds`.
- `crates/exo-dag/src/mmr.rs`: `verify_proof()` checks
  `proof.leaf_count == 0 || position >= proof.leaf_count` and returns `false`.
- `crates/exo-dag/src/mmr.rs`: `mmr::tests::proof_out_of_bounds` proves invalid
  proof generation fails with the typed error.
- `crates/exo-dag/src/mmr.rs`:
  `mmr::tests::proof_for_real_leaf_fails_out_of_bounds_position` proves verifier
  replay at an invalid position fails closed.

## Remediation Result

No production code change was required. The reported empty-proof-on-invalid-position
behavior did not reproduce against current `main`.
