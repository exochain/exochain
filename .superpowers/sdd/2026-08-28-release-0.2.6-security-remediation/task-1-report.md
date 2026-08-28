# Task 1 Implementer Report

## Provenance

- Base SHA: `de564286cc555935b0356c58c73662ca1fb676f3`
- Implementation commit SHA: `0cc5d62dd0f6b1a6e7eca5800c043e8a40891e70`
- Implementation commit message: `security: fail closed on legacy proofs and PDP mutations`
- Path classification: every implementation path is EXOCHAIN core or a core runtime adapter. This report is task-local implementation evidence. No imported HTML or other downloaded evidence was edited or committed.

## Files Changed

- `Cargo.toml`
- `Cargo.lock`
- `crates/exo-proofs/src/snark.rs`
- `crates/exo-proofs/src/verifier.rs`
- `crates/exo-pdp/Cargo.toml`
- `crates/exo-pdp/src/http.rs`
- `crates/exo-node/Cargo.toml`
- `crates/exo-node/src/main.rs`
- `crates/exo-node/src/auth.rs`
- `crates/exo-node/src/mcp/mod.rs`
- `crates/exo-node/src/avc.rs`
- `crates/exo-node/src/passport.rs`
- `crates/exo-node/src/zerodentity/tests.rs`

The final three node files contain test-only construction call-site updates required by the intentional `BearerAuth` construction-boundary change; they do not change production behavior.

## RED Evidence

Each regression was added and executed before its corresponding production change.

1. Command:

   ```text
   cargo test -p exochain-proofs --features unaudited-pedagogical-proofs legacy_snark_verify_refuses -- --nocapture
   ```

   Observed result: exit 101. Both new regressions failed their typed-error assertions because the feature-enabled direct and unified legacy SNARK verifiers returned `Ok(true)` for a forged public hash chain.

2. Command:

   ```text
   cargo test -p exochain-pdp http -- --nocapture
   ```

   Observed result: exit 101. The real exported-router regressions observed status 200 instead of 401 for an unauthenticated key-registration mutation, 200 instead of 413 for an oversized body, and 200 instead of 400 for a signed delegation containing 65 scope entries.

3. Command:

   ```text
   cargo test -p exochain-node bearer_tokens_are_compared -- --nocapture
   ```

   Observed result: exit 101 during compilation with `E0433` because `BearerTokenVerifier` did not exist.

4. Command:

   ```text
   cargo test -p exochain-node mcp_authorization_preserves -- --nocapture
   ```

   Observed result: exit 101 during compilation with `E0609` because `SseState` had no `bearer_verifier` field and still exposed the plaintext `bearer_token` representation.

## GREEN and Control Evidence

All Task 1 Step 7 commands were rerun after the implementation:

1. `cargo test -p exochain-proofs --features unaudited-pedagogical-proofs legacy_snark_verify_refuses -- --nocapture` — exit 0; 2 matching tests passed, 0 failed.
2. `cargo test -p exochain-proofs` — exit 0; library and integration suites passed, with the repository's existing ignored proof tests remaining ignored.
3. `cargo test -p exochain-pdp http -- --nocapture` — exit 0; 6 matching tests passed, 0 failed.
4. `cargo test -p exochain-node bearer_tokens_are_compared -- --nocapture` — exit 0; 1 matching test passed, 0 failed.
5. `cargo test -p exochain-node mcp_authorization_preserves -- --nocapture` — exit 0; 1 matching test passed, 0 failed.
6. `cargo test -p exochain-node authority_evidence -- --nocapture` — exit 0; 1 matching test passed, 0 failed.
7. `cargo test -p exochain-node --no-run` — exit 0; all node test executables compiled.
8. `cargo deny check` — exit 0; advisories, bans, licenses, and sources passed. The command retained pre-existing informational warnings about duplicate dependency versions and yanked transitive `spin 0.9.8`.

Additional controls:

- `cargo test -p exochain-proofs --features unaudited-pedagogical-proofs -- --nocapture` — exit 0; the full feature-enabled library suite passed 131 tests with 1 ignored, and all integration suites passed.
- `cargo clippy -p exochain-proofs -p exochain-pdp -p exochain-node --all-targets -- -D warnings` — exit 0.
- `cargo +nightly fmt --all -- --check` — exit 0.
- `git diff --check` — exit 0.
- A source bypass search found no remaining local `constant_time_eq` function, unequal-length bearer early return, plaintext MCP bearer field, or old PDP mutation constructor at the node wiring point.

## Design and Compatibility Notes

- Direct legacy SNARK verification and the unified SNARK verifier now return `ProofError::UnauditedImplementation { api: "snark::verify" }` before parsing or equality checks, including when `unaudited-pedagogical-proofs` is enabled. Legacy DTO construction and decoding compatibility remains available, but the hash skeleton is documented only as a structural artifact.
- `PdpMutationAuthorizer` is opaque and cloneable. The complete mutation router requires it at construction. Existing `pdp_router` and `pdp_router_with_persistence` signatures remain source-compatible but deliberately expose only read and independent-verification routes, so they cannot silently install mutations.
- The node constructs the PDP authorizer from the canonical node bearer verifier. Mutation routes apply a 1 MiB `DefaultBodyLimit`, and delegation rejects more than 64 raw scope items before allocating and parsing the second permission vector.
- Node, route-scoped LiveSafe, and MCP configured bearers are prehashed once to fixed 32-byte BLAKE3 digests. Every presented bearer is independently normalized to 32 bytes and compared with exact-pinned `subtle = "=2.6.1"` through `ConstantTimeEq`. Candidate digest storage is zeroized after comparison; missing or malformed MCP headers remain 401 and well-formed wrong tokens remain 403.
- Signed mandate behavior, persistence rollback tests, read routes, x402 routing, authorized mutation behavior, and authority-evidence controls remain green.

## Residual Risks and Claim Boundary

- The pedagogical SNARK setup/prove DTO path remains constructible for compatibility, but neither public legacy verification entry point can accept it as verified evidence.
- PDP's opaque authorizer intentionally returns only allow/deny; at this adapter boundary a rejected mutation maps to 401, while the canonical node and MCP bearer middleware preserves its established 401/403 distinctions.
- `cargo deny check` passed despite its existing duplicate-version and yanked-transitive-dependency warnings; this task did not change those dependency families.
- No process was deployed and no live node runtime was started. The evidence establishes source, unit/integration-test, compilation, lint, formatting, and dependency-policy results only.
