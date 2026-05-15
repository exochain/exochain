# Gauntlet Proofs and Observability Validation - 2026-05-15

## Scope

This record verifies a narrow cluster of Gauntlet findings against current
`main` before attempting remediation. The external report is treated as
imported evidence, not source-of-truth code.

Findings covered:

- F-025: SNARK/STARK/ZKML stubs wired as production verification authority.
- F-069: receipt integrity sentinel always returns healthy.
- F-070: governance event broadcast uses `Timestamp::ZERO`.
- F-164: MCP middleware provenance timestamp is hardcoded.

No production code change was justified by this pass. Each reported behavior is
already blocked, fail-closed, or covered by current regression tests.

## Path Classification

| Path | Classification | Notes |
| --- | --- | --- |
| `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md` | Imported evidence | External finding source only. |
| `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md` | Imported evidence | External severity/readout source only. |
| `/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv` | Imported evidence | External finding index only. |
| `crates/exo-proofs/src/lib.rs` | EXOCHAIN core | Proof facade and default unaudited-proof guard. |
| `crates/exo-proofs/src/snark.rs` | EXOCHAIN core | Gated SNARK skeleton entry points. |
| `crates/exo-proofs/src/stark.rs` | EXOCHAIN core | Gated STARK skeleton entry points. |
| `crates/exo-proofs/src/zkml.rs` | EXOCHAIN core | Gated ZKML skeleton entry points. |
| `crates/exo-proofs/src/verifier.rs` | EXOCHAIN core | Unified verifier facade. |
| `crates/exo-proofs/tests/refusal.rs` | EXOCHAIN core | Default-build refusal regression tests. |
| `crates/exo-gateway/src/graphql.rs` | Core runtime adapter | GraphQL proof query refuses arbitrary proof IDs. |
| `crates/exo-node/src/sentinels.rs` | Core runtime adapter | Runtime sentinel health checks. |
| `crates/exo-node/src/reactor.rs` | Core runtime adapter | Governance event broadcast path. |
| `crates/exo-node/src/api.rs` | Core runtime adapter | Governance broadcast HTTP entrypoint. |
| `crates/exo-node/src/mcp/middleware.rs` | Core runtime adapter | MCP constitutional invocation verifier. |
| `docs/audit/GAUNTLET-PROOFS-OBSERVABILITY-VALIDATION-2026-05-15.md` | Imported-evidence triage documentation | This validation record. |

## Dispositions

| Finding | Current disposition | Evidence |
| --- | --- | --- |
| F-025 | Stale / already remediated | `exo-proofs` is explicitly unaudited and default-off. Public proof entry points call `guard_unaudited`, the default build returns `ProofError::UnauditedImplementation`, no owned downstream Cargo manifest enables `unaudited-pedagogical-proofs`, and GraphQL `verifyProof` returns `valid: false` with `proofType: "Unavailable"` instead of treating an arbitrary ID as verified. |
| F-069 | Stale / already remediated | `check_receipt_integrity` now loads recent receipts, calls `receipt.verify_hash()`, fails closed on store/decode/hash errors, and has focused tests for empty stores, decode failure, tampered receipts, and source-level hash verification. |
| F-070 | Stale / already remediated | The raw admin governance broadcast shortcut is feature-gated off by default. The reactor broadcast path now publishes a non-zero monotonic timestamp and signs the canonical governance event envelope. |
| F-164 | Stale / already remediated | MCP middleware no longer hardcodes the reported fixed timestamp and does not fabricate invocation context. The current source guard checks the production section for both fabricated context fields and the fixed timestamp. |

## Validation Commands

Imported-evidence lookup:

```bash
rg -n "F-025|SNARK|STARK|ZKML|proof verification|pedagogical|stub" "/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings"
rg -n "F-069|receipt integrity|check_receipt_integrity|sentinel" "/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings"
rg -n "F-070|HLC|SystemTime::now|Instant::now|chrono::Utc::now|broadcast|timestamp" "/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-findings.md" "/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/gauntlet-deep-analysis.md" "/private/tmp/exochain-gauntlet-findings/Exochain Gauntlet Findings/da-findings.tsv"
```

Current-code searches:

```bash
rg --files -g '*snark*' -g '*stark*' -g '*zkml*' -g '*proof*' crates packages tools governance
rg -n "unaudited-pedagogical-proofs" Cargo.toml crates packages tools .github governance docs --glob '!target/**' --glob '!docs/superpowers/**'
rg -n "SystemTime::now|Instant::now|chrono::Utc::now|Utc::now|std::time::SystemTime|std::time::Instant" crates packages tools governance .github docs --glob '!docs/superpowers/**' --glob '!target/**'
```

Focused runtime validation:

```bash
cargo test -p exo-proofs -- --nocapture
cargo test -p exo-proofs --features unaudited-pedagogical-proofs -- --nocapture
cargo test -p exo-gateway query_verify_proof_refuses_arbitrary_proof_id --features unaudited-gateway-graphql-api -- --nocapture
cargo test -p exo-node receipt_integrity -- --nocapture
cargo test -p exo-node broadcast_governance_event -- --nocapture
cargo test -p exo-node broadcast_endpoint_refuses_admin_shortcut_without_feature_flag -- --nocapture
cargo test -p exo-node production_source_does_not_fabricate_mcp_context -- --nocapture
```

Observed results:

- `cargo test -p exo-proofs -- --nocapture`: passed, 22 unit tests and 3 refusal integration tests.
- `cargo test -p exo-proofs --features unaudited-pedagogical-proofs -- --nocapture`: passed, 113 unit tests.
- `cargo test -p exo-gateway query_verify_proof_refuses_arbitrary_proof_id --features unaudited-gateway-graphql-api -- --nocapture`: passed, 1 focused test.
- `cargo test -p exo-node receipt_integrity -- --nocapture`: passed, 4 focused tests.
- `cargo test -p exo-node broadcast_governance_event -- --nocapture`: passed, 3 focused tests.
- `cargo test -p exo-node broadcast_endpoint_refuses_admin_shortcut_without_feature_flag -- --nocapture`: passed, 1 focused test.
- `cargo test -p exo-node production_source_does_not_fabricate_mcp_context -- --nocapture`: passed, 1 focused test.

## Residual Risk

F-025 remains an architectural capability gap, not a live production verifier
acceptance bug: the unaudited proof skeleton is intentionally default-off and
must not be enabled for production trust claims. A future production ZK backend
should land as a separate core remediation with real backend selection,
canonical proof statement definitions, adversarial proof fixtures, and a
dedicated council assessment.
