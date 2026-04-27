# exo-proofs

**⚠️ UNAUDITED — NOT PRODUCTION CRYPTOGRAPHY**

This crate is a *pedagogical / structural* implementation of zero-knowledge
proof primitives (SNARK, STARK, zkML, and a verifier facade). It exists to
demonstrate the **shape** of the APIs EXOCHAIN will eventually require — it
is **not** a cryptographically sound proof system.

## Why this crate refuses to run by default

In the default build, every public proof entry point returns
`Err(ProofError::UnauditedImplementation { .. })`. This is deliberate.

Doctrine: **"Never stub."** We do not ship code that *claims* a capability it
does not have. Rather than leaving silently-passing placeholders, the proof
functions gate themselves behind a Cargo feature whose very name is the
warning label:

```toml
[dependencies]
exo-proofs = { path = "../exo-proofs", features = ["unaudited-pedagogical-proofs"] }
```

If a consumer of this crate forgets to enable the feature, their build
compiles but every call to `snark::prove / verify`, `stark::prove_stark /
verify_stark`, `zkml::prove_inference / verify_inference`, and
`verifier::verify_any` returns a hard refusal error — not a fake "proof
valid" boolean.

## What *is* honest in this crate

- **API shape** — the `Circuit` / `ConstraintSystem` / `ProvingKey` /
  `VerifyingKey` / `Proof` / `StarkProof` / `InferenceProof` types are
  reasonable first-cut shapes for when a real proof backend is wired in.
- **Domain separation on commitments** — hashes are computed with
  domain-separated BLAKE3 prefixes (`"mmr:leaf:"`, `"snark:c:"`, etc.), so
  when the crate *is* replaced with a real backend, the commitment scheme
  around it carries no collision hazards from this skeleton.
- **`ModelCommitment` / `HumanAttestation` / Daubert checklist** — these
  are ordinary structured-data types, not cryptographic claims. They remain
  usable even with the feature off.

## What is **not** honest

Inside the proof routines themselves:

- SNARK "curve points" (`a`, `b`, `c`) are 32-byte hash-based stand-ins.
- STARK low-degree tests and FRI folding are structural, not a sound IOP.
- zkML "proof" binds `(model_hash, input_hash, output_hash)` via a hash
  chain — it is a *signed statement*, not a zero-knowledge proof.

If you need to ship any user-facing or governance-relevant claim that
depends on zero-knowledge soundness, replace this crate with a real proving
backend (arkworks / halo2 / plonky2 / risc0 / etc.) **before** enabling
the feature flag anywhere downstream.

## Tests

- **Default build (feature OFF):** `cargo test -p exo-proofs` runs the
  refusal integration tests in `tests/refusal.rs`, verifying that every
  gated entry point errors out. Unit tests inside each module are
  `#[cfg(feature = "unaudited-pedagogical-proofs")]` and do not run.
- **Pedagogical build (feature ON):** `cargo test -p exo-proofs --features
  unaudited-pedagogical-proofs` runs the full 79-test suite exercising the
  skeleton's internal consistency.

## Status

| Module    | State | Replace with |
|-----------|-------|--------------|
| `circuit` | OK structural | (keep — shape is sound) |
| `snark`   | UNAUDITED | arkworks / halo2 / plonky2 |
| `stark`   | UNAUDITED | winterfell / risc0 STARK |
| `zkml`    | UNAUDITED | EZKL / jolt / specialized backend |
| `verifier`| facade  | re-route to real backend |

## License

Apache-2.0 OR MIT, per workspace.
