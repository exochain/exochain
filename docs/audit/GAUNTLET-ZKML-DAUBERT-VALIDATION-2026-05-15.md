# Gauntlet F-150 ZKML Daubert Validation

Date: 2026-05-15

## Classification

- Finding: F-150, `prove_inference()` vs `prove_inference_with_provenance()`
  Daubert consequence unspecified.
- Report source: imported evidence from `Exochain Gauntlet Findings`.
- Owned path reviewed: `crates/exo-proofs/src/zkml.rs`.
- Path classification: EXOCHAIN core.

## Current-Main Disposition

The finding is stale in current `main`. The ZKML proof model now has an explicit
fail-closed Daubert admissibility boundary:

- `InferenceProof::daubert_admissibility_status()` returns a typed
  `DaubertAdmissibility` decision.
- Missing prompt hash, missing or invalid human attestation, inconsistent
  AI-delta evidence, missing checklist, and incomplete checklist all return
  `DaubertAdmissibility::Inadmissible`.
- A basic `prove_inference()` proof remains backward-compatible and deliberately
  carries no fabricated human attestation.
- `prove_inference_with_provenance()` binds a distinct prompt hash for Daubert
  disclosure.
- `crates/exo-proofs/README.md` states the current ZKML proof is a signed
  statement rather than a production zero-knowledge proof backend.

## Verification Evidence

Commands run from `/Users/bobstewart/dev/exochain`:

```bash
cargo test -p exo-proofs daubert_admissibility --features unaudited-pedagogical-proofs -- --nocapture
cargo test -p exo-proofs human_attestation_required_for_ai_output --features unaudited-pedagogical-proofs -- --nocapture
cargo test -p exo-proofs zkml_source_exposes_fail_closed_daubert_admissibility_status --features unaudited-pedagogical-proofs -- --nocapture
```

All commands passed on current `main`.

## Remediation Result

No production code change was required. The reported absence of an explicit
Daubert consequence did not reproduce against current `main`.
