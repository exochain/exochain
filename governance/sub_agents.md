# Sub-Agent Charters

Historical 2026-03-19 sub-agent completion record. Numeric status claims are superseded by `tools/repo_truth.sh` and the Wave E Basalt audit.

## A) SPEC_GUARDIAN (Legislative) — DONE

* **Mission**: Ensure implementation strictly follows EXOCHAIN v2.2 Specification and maintain traceability.
* **Inputs**: `EXOCHAIN_Specification_v2.2.pdf`, `EXOCHAIN-FABRIC-PLATFORM.md`.
* **Outputs**: `traceability_matrix.md`, ADR reviews, "Non-negotiable invariants checklist".
* **Definition of Done**: Traceability matrix maps every Spec section to code/tests; no unmapped requirements.
* **Status**: **DONE, needs Basalt refresh** — Current traceability rows are 83 implemented, 1 partial, and 2 planned.

## B) ARCHITECTURE_AGENT (Legislative) — DONE

* **Mission**: Efficient, modular crate design aligned with Spec phases.
* **Inputs**: Spec Phases, Rust Ecosystem Best Practices.
* **Outputs**: Repo layout, `Cargo.toml` workspace, crate boundaries.
* **Definition of Done**: Use of `workspace` pattern, circular dependency check pass, clear API boundaries.
* **Status**: **DONE** — 20 workspace packages are established in `Cargo.toml` / `cargo metadata`.

## C) CRYPTO_CANONICAL_AGENT (Judicial) — DONE

* **Mission**: Implement deterministic cryptographic substrate (CBOR, BLAKE3, Ed25519) with cross-platform compatibility.
* **Inputs**: Spec Section 9.1 (Event Hashing), Section 9.5 (RiskAttestation).
* **Outputs**: `exo-core` crate, `cross-impl-test` harness, test vectors.
* **Definition of Done**: Cross-implementation hash tests pass between Rust and JS Reference.
* **Status**: **DONE** — BLAKE3, Ed25519, post-quantum `Signature` enum (Ed25519/PostQuantum/Hybrid), and cross-implementation tests all passing.

## D) CONSENSUS_DAG_AGENT (Executive) — DONE

* **Mission**: Implement DAG storage, appending, and Hybrid Logical Clocks.
* **Inputs**: Spec Section 9.2 (HLC), Section 9.4 (Checkpoints).
* **Outputs**: `exo-dag` crate, `DAGStore` trait, `append()` logic.
* **Definition of Done**: `verify_integrity()` passes on complex DAG topologies (proptest).
* **Status**: **DONE** — DAG engine, BFT consensus adapter, HLC, SMT, and MMR all implemented and tested.

## E) PROOFS_INDEXER_AGENT (Executive/Judicial) — DONE

* **Mission**: Implement verifiable query structures (MMR, SMT) and proofs.
* **Inputs**: Spec Section 9.4 (Split Roots).
* **Outputs**: MMR/SMT implementations, `EventInclusionProof` struct.
* **Definition of Done**: Proof generation and verification roundtrip tests pass.
* **Status**: **DONE** — SNARK, STARK, ZKML proof systems and verifier infrastructure complete.

## F) IDENTITY_CONSENT_AGENT (Executive) — DONE

* **Mission**: Logic for Identity, Consent, and Bailment fabrics.
* **Inputs**: Spec Section 10 (Identity), Section 11 (Functional Reqs).
* **Outputs**: `exo-identity`, `exo-consent`, `DidDocument`, `Policy` structs.
* **Definition of Done**: Functional tests for Lifecycle (Create -> Rotate -> Revoke).
* **Status**: **DONE** — DID, key management, Shamir secret sharing, vault, consent, and bailment all implemented.

## G) GATEKEEPER_TEE_AGENT (Executive/Judicial) — DONE

* **Mission**: Enforce TRUSTED boundaries for vault access.
* **Inputs**: Spec Section 12 (Gatekeeper Trust).
* **Outputs**: `exo-gatekeeper` interfaces, Mock TEE for dev.
* **Definition of Done**: Policy enforcement tests (Consent -> AccessLogged), TEE Attestation mock flow.
* **Status**: **DONE** — Kernel, invariants, combinators, holon, MCP integration complete. TEE attestation implemented with production gate for hardware TEE.

## H) SECURITY_THREATS_AGENT (Judicial) — DONE

* **Mission**: Maintain Threat Model and ensure coverage.
* **Inputs**: Spec Section 13 (Threat Model).
* **Outputs**: `threat_matrix.md`, fuzzing targets, `cargo-audit` config.
* **Definition of Done**: Every threat in Section 13 has > 1 corresponding test case.
* **Status**: **DONE** — Current threat matrix tracks 14 threats, all marked implemented.

## I) QA_TDD_AGENT (Judicial) — DONE

* **Mission**: Enforce Testing Pyramid and Acceptance Criteria.
* **Inputs**: Spec Section 16 (Acceptance Criteria).
* **Outputs**: Test harnesses, Integration tests, Fuzz targets.
* **Definition of Done**: Section 16 Acceptance Criteria are automated and passing.
* **Status**: **DONE** — Current workspace inventory lists 2,955 tests across 20 packages and 266 Rust files.

## J) DEVOPS_RELEASE_AGENT (Judicial) — DONE

* **Mission**: CI/CD Pipelines and Release Quality Gates.
* **Inputs**: Quality Gate Policies.
* **Outputs**: `.github/workflows/ci.yml`, Release scripts, `deny.toml`.
* **Definition of Done**: CI pipeline enforces coverage, formatting, and audit checks.
* **Status**: **DONE** — CI pipeline at `.github/workflows/ci.yml` with 20 numbered gates plus the required aggregator, `cargo deny` integration, and coverage enforcement per CR-001 Section 8.8.

## K) DOCS_OSS_GOVERNANCE_AGENT (Legislative) — DONE

* **Mission**: Open Source Community Governance and Documentation.
* **Inputs**: OSS Best Practices, Spec.
* **Outputs**: `README.md`, `LICENSE`, `CONTRIBUTING.md`, `GOVERNANCE.md`.
* **Definition of Done**: Documentation is complete, accessible, and inclusive.
* **Status**: **DONE** — 7+ documentation files, user manual, ASI report, getting started guide, crate reference, constitutional proofs, and 5-panel council reports all published.
