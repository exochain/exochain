# Threat Model & Test Matrix

Based on Spec Section 13. Updated 2026-03-19 after council-driven implementation.

**Status key:** 🟢 Implemented (tests passing) | 🟡 Partial (core logic exists, gaps remain) | 🔴 Planned

## Threat Matrix

| ID | Threat | Mitigation (Code) | Crate(s) | Tests | Status |
|---|---|---|---|---|---|
| **T-01** | **Key Exfiltration** | `KeyStore` with `zeroize`-on-drop, key rotation, revocation, status tracking | `exo-identity/key_management.rs` | 15 unit | 🟢 Implemented |
| **T-02** | **Score Replay** | `verify_attestation()` validates attester key binding; `RiskAttestation` with subject DID, level, expiry | `exo-identity/risk.rs` | 8 unit | 🟢 Implemented |
| **T-03** | **BFT Liveness** | 2f+1 quorum via `quorum_size()`, `propose()`/`vote()`/`check_commit()`/`commit()` cycle, duplicate vote rejection, non-validator rejection | `exo-dag/consensus.rs` | 12 unit | 🟢 Implemented |
| **T-04** | **Sybil Attack** | 6 sub-threat taxonomy: `verify_independence()` checks signing keys, attestation chains, control metadata; `detect_coordination()` timing analysis (100ms threshold); independence-aware quorum counting | `exo-governance/crosscheck.rs`, `exo-governance/quorum.rs`, `exo-escalation/escalation.rs` | 11 + 12 + 10 unit | 🟢 Implemented |
| **T-05** | **Vault Breach** | `VaultEncryptor` with XChaCha20-Poly1305 AEAD, HKDF-SHA256 key derivation, DID-bound associated data, zeroize-on-drop | `exo-identity/vault.rs` | 9 unit | 🟢 Implemented |
| **T-06** | **Eclipse Attack** | `RateLimiter` + `AsnPolicy` with min ASN diversity, `select_diverse_peers()` round-robin, `rotate_peers()` stale eviction, unknown ASN grouped as single bucket | `exo-api/p2p.rs` | 31 unit | 🟢 Implemented |
| **T-07** | **Replay (Events)** | `HybridClock` monotonic `now()`, causal `update()` merge, `ClockDrift` rejection, injectable wall clock for testing | `exo-core/hlc.rs` | 15 unit | 🟢 Implemented |
| **T-08** | **Sig Forgery** | Real `ed25519_dalek::VerifyingKey::verify()` in authority chain verification; `SignerType` prefix binding (human 0x01 / AI 0x02) in signed payload | `exo-core/crypto.rs`, `exo-authority/chain.rs`, `exo-gatekeeper/mcp.rs` | 10 + 5 adversarial | 🟢 Implemented |
| **T-09** | **HLC Manipulation** | `MAX_DRIFT_MS` (5000ms) enforcement, `ClockDrift` error on forward skew, monotonic guarantee on backward skew | `exo-core/hlc.rs` | 15 unit | 🟢 Implemented |
| **T-10** | **DoS API** | `RateLimiter` with per-peer counting (100 req cap), reset capability | `exo-api/p2p.rs` | 2 unit | 🟢 Implemented |
| **T-11** | **Admin Bypass** | CGR Kernel immutability (constitution hash verified on every `adjudicate()`), `SeparationOfPowers` invariant, `NoSelfGrant` invariant, `KernelImmutability` invariant | `exo-gatekeeper/kernel.rs`, `exo-gatekeeper/invariants.rs` | 14 + 30 unit | 🟢 Implemented |
| **T-12** | **Holon Key Theft** | TEE attestation with `TeeEnvironment` production gate; `Simulated` rejected in Production; `#[cfg(not(feature = "allow-simulated-tee"))]` compile-time strip; secure-by-default | `exo-gatekeeper/tee.rs` | 28 unit | 🟢 Implemented |
| **T-13** | **Capability Esc.** | CGR Kernel `adjudicate()` with `NoSelfGrant` invariant; authority chain scope narrowing; AI delegation ceiling (`TNC-09`) | `exo-gatekeeper/kernel.rs`, `exo-authority/chain.rs`, `decision-forum/tnc_enforcer.rs` | 14 + 19 + 13 unit | 🟢 Implemented |

| **T-14** | **Auth Chain Sig Forgery** | Ed25519 signature verification on every `AuthorityLink` in `check_authority_chain_valid()`; `signable_payload()` commits grantor/grantee/permissions; forged, empty, or wrong-key signatures produce `InvariantViolation` | `exo-gatekeeper/invariants.rs`, `exo-gatekeeper/types.rs` | 5 adversarial (forged sig, empty sig, wrong key, tampered payload, valid chain accepted) | 🟢 Implemented |
| **T-15** | **Emergency Per-Actor Bypass** | `check_per_actor_limit()` hard gate; `EmergencyPolicy.max_per_quarter_per_actor` (default 1); expired actions excluded; different actors unaffected; limit=0 disables | `decision-forum/emergency.rs` | 5 unit (first ok, second blocked, different actor ok, expired excluded, zero=unlimited) | 🟢 Implemented |
| **T-16** | **AI Self-Declared Ceiling** | `TncContext.ai_ceilings_externally_verified` flag; when false, TNC-09 restricts all AI signers to Routine (fail-closed); when true, delegation-registry ceiling is enforced | `decision-forum/tnc_enforcer.rs` | 4 adversarial (unverified blocks non-routine, unverified allows routine, verified allows declared, verified blocks over-ceiling) | 🟢 Implemented |
| **T-17** | **Post-Quantum Harvest** | `Signature::PostQuantum` and Hybrid PQ component are stub-level; SECURITY-NOTE added to `crypto::verify()` documenting gap; ML-DSA (NIST FIPS 204) implementation required for production readiness | `exo-core/crypto.rs` | — | 🟡 Partial |

## Summary

| Status | Count | Threats |
|--------|-------|---------|
| 🟢 Implemented | 16 | T-01, T-02, T-03, T-04, T-05, T-06, T-07, T-08, T-09, T-10, T-11, T-12, T-13, T-14, T-15, T-16 |
| 🟡 Partial | 1 | T-17 |
| 🔴 Planned | 0 | — |

## Resolved Remediation Tickets

All three remediation tickets have been resolved and closed:

- **#11 (T-05):** Resolved in commit `0371a4b` — VaultEncryptor with XChaCha20-Poly1305, HKDF-SHA256, AEAD binding to DID, zeroize-on-drop. 9 tests.
- **#12 (T-06):** Resolved in commit `0371a4b` — AsnPolicy with diversity enforcement, round-robin selection, stale peer rotation. 9 tests.
- **#13 (T-12):** Resolved in commit `0371a4b` — TeeEnvironment production gate, compile-time feature flag, secure-by-default. 9 tests.

## Security Policies

1. **Dependency Audit**: `cargo-deny` config (`deny.toml`) bans copyleft licenses, denies known vulnerabilities, bans OpenSSL (pure-Rust crypto only).
2. **Fuzzing**: Continuous fuzzing planned on `EventEnvelope` deserializers and signature verification inputs.
3. **No Unsafe**: `#![forbid(unsafe_code)]` enforced across all crates.
4. **Determinism**: `#[deny(clippy::float_arithmetic)]` workspace-wide; `BTreeMap` only (no `HashMap`); HLC for all temporal ordering.
5. **Post-Quantum**: `Signature` enum supports `Ed25519`, `PostQuantum`, and `Hybrid` variants for migration readiness.
