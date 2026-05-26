# CyberMedica Production Trust Activation Gates

This register protects CyberMedica from exposing regulated clinical QMS workflows as Exochain-backed production trust claims before the required evidence exists. A listed item may and should be developed through explicit service contracts, deterministic fixtures, local adapters, contract tests, inactive trust-state UI, and fail-closed behavior. It must not be exposed as an active production trust claim until the verification condition is satisfied.

## What Can Be Built Now

| Build activity | Allowed now? | Boundary |
|---|---:|---|
| CyberMedica domain models and QMS workflows | Yes | Must not claim live Exochain/root enforcement before activation evidence. |
| Adapter interfaces for gateway, node, Decision Forum, receipts, and root verification | Yes | Must fail closed when the runtime path is absent, rejected, or unverified. |
| Deterministic fixtures and contract tests | Yes | Fixtures prove behavior; they do not mint production authority. |
| UI states for pending, inactive, unavailable, denied, and verified trust fabric | Yes | Default production trust state is inactive until verified. |
| PHI/PII non-anchoring tests and evidence manifest tests | Yes | No raw sensitive content in receipts, anchors, logs, telemetry, or exports. |
| Production root-backed authority claims | No | Requires verified root bundle, 13-certifier DKG evidence, 7-of-13 signing evidence, and deployed verifier path. |

## Gated Production Claims

| ID | Gated Production Claim or Runtime Feature | Source evidence | Why gated | Required verification | Minimum CyberMedica test |
|---|---|---|---|---|---|
| PTAG-001 | Root-backed production authority | `crates/exo-root/src/ceremony.rs`, `dkg.rs`, `signing.rs`, `bundle.rs`, `portal.rs`; user 7/13 clarification | Root activation evidence is not present in this seed. | 13 rostered independent certifiers; 100% root genesis FROST Ristretto255 DKG completion; verified root trust bundle; 7-of-13 threshold signing evidence; deployed verifier path. | App shows trust inactive without verified root bundle; root bundle verification positive/negative tests. |
| PTAG-002 | ZK proof-backed clinical privacy claim | `crates/exo-proofs/src/lib.rs` | Proof crate is explicitly unaudited, pedagogical, and default-off. | Audited production proof implementation, enabled feature posture, CI and cryptographic review. | Claim guard denies ZK wording when production proof capability is absent. |
| PTAG-003 | CrossChecked-backed anchoring | `crates/exo-node/src/api.rs` | External anchor path refuses by default because proof URL/signature/tenant/authority verification is not established. | Enabled runtime path with tenant auth, authority chain, external proof verification, fail-closed tests. | Anchor request fails closed unless all verification inputs pass. |
| PTAG-004 | Raw admin governance endpoint for clinical approvals | `crates/exo-node/src/api.rs` | Propose/broadcast/validator changes refuse unless unaudited admin shortcut feature is enabled. | Adjudicated governance path through gatekeeper/quorum/Decision Forum. | Raw admin route unavailable in production config. |
| PTAG-005 | Decision Forum approval without human gate | `crates/decision-forum/src/human_gate.rs`, `tnc_enforcer.rs` | Self-declared human actors are insufficient; AI ceiling is enforced. | External human DID verification source and mapped approval policy. | AI cannot approve launch/enrollment/CAPA closure; unverified human DID denied. |
| PTAG-006 | Decision Forum state change through raw transition | `crates/decision-forum/src/decision_object.rs` | Production path requires `transition_adjudicated_at`; raw transition returns conflict outside test-only context. | Adapter uses adjudicated transition only. | Raw transition path unreachable; missing kernel verdict denies. |
| PTAG-007 | Clinical consent equivalence from generic bailment alone | `crates/exo-consent/src/bailment.rs`, `policy.rs`, `contract.rs` | Exochain implements bailment/consent primitives; clinical informed consent requirements need domain mapping. | Bob/legal/clinical mapping from consent objects to clinical consent controls. | Consent grant/revoke tests plus clinical policy fixture tests. |
| PTAG-008 | Tenant isolation as full data isolation from registry alone | `crates/exo-tenant/src/tenant.rs` | Tenant registry metadata does not prove storage/query isolation. | CyberMedica storage tenancy model and cross-tenant denial tests. | Tenant A cannot read/write/export Tenant B across every route/job/export. |
| PTAG-009 | PHI/PII-safe anchoring without fixture proof | `crates/exo-node/src/provenance.rs`, `crates/exo-legal/src/evidence.rs` | Hash-only anchors can still leak sensitive metadata. | PHI/PII/sponsor-confidential field classification and automated fixture checks. | No raw sensitive fixtures in receipts, DAG payloads, logs, telemetry, health, exports. |
| PTAG-010 | Authority-backed clinical role claims without role mapping | `crates/exo-authority/src/permission.rs`, `chain.rs`, `delegation.rs` | Exochain permissions are not a clinical role taxonomy. | CyberMedica role-to-permission/quorum/Decision Forum actor mapping. | Expired/revoked/out-of-scope roles denied for each regulated action. |
| PTAG-011 | Syntaxis-generated clinical governance workflow | `tools/syntaxis/node_registry.json`, `generate_workflow.py` | Registry references may not map cleanly to current modules. | Registry-to-code validation, generated workflow compile, generated tests pass. | Generated QMS workflow compiles and fails closed on invalid node/edge. |
| PTAG-012 | 0dentity behavioral/device trust scoring | `crates/exo-node/src/zerodentity/*` | Behavioral/device axes are disabled behind unaudited flags and public write persistence is partial. | Enabled production path, privacy review, persistence and test evidence. | Feature disabled by default; claim text absent unless enabled and tested. |
| PTAG-013 | Economy settlement or billing trust | `crates/exo-economy/src/lib.rs` | Economy code is scaffold-like with zero launch guarantee. | Production settlement contract, regulatory/accounting review, tests. | Billing/export routes do not claim settlement finality. |
| PTAG-014 | CommandBase enforcement | `AGENTS.md`, `README.md`, `command-base/*` | Adjacent surface not inventoried; no trust by proximity. | Intake record, code inventory, runtime adapter proof, fail-closed tests. | CyberMedica UI does not cite CommandBase as enforcement source. |
| PTAG-015 | ExoForge/Archon as governance authority | `AGENTS.md`, `docs/guides/ARCHON-INTEGRATION.md` | Agent workflow outputs are untrusted until validated. | Bounded workflow config, human review, source guard, tests. | Agent output cannot authorize merge, trust claim, or governance decision. |
| PTAG-016 | Gateway-backed enforcement without adapter tests | `crates/exo-gateway/src/auth.rs`, `routes.rs`, `server.rs`; `.github/workflows/ci.yml` | Runtime adapter areas have scoped coverage caveats. | CyberMedica adapter contract and fail-closed tests. | Gateway timeout, reject, malformed response, and unavailable service all deny action. |
| PTAG-017 | Node-backed receipt claim without receipt sync tests | `crates/exo-node/src/store.rs`, `api.rs`, `provenance.rs` | Receipt path must prove action hash, signature, and payload boundaries. | Receipt insert/load/query tests against selected deployment mode. | Receipt.action_hash matches committed node; no raw payload in provenance response. |
| PTAG-018 | WASM/browser trust path for PHI workflows | `crates/exochain-wasm/*`, `.github/workflows/ci.yml` | Browser adapter increases exposure and needs export sync/fail-closed proof. | WASM export sync, secret exposure tests, browser fail-closed tests. | Browser route cannot hold root/signing secrets and denies missing trust fabric. |

## Required Verification Commands

Run these in `/Users/bobstewart/dev/exochain/exochain` before activating any gated production trust claim:

```bash
git branch --show-current
git rev-parse HEAD
git status --short
tools/repo_truth.sh --json --list-tests
cargo metadata --format-version 1
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

For CyberMedica implementation work, add project-native gates:

```bash
# Exact command depends on the selected stack.
# Required categories: unit, integration, adapter contract, privacy fixtures,
# coverage, lint/typecheck, dependency audit, secret scan, and build.
```

## Claim Lifting Criteria

A gated claim can become active only when:

1. The Exochain source path is current against local branch/commit.
2. The enabled runtime path is identified.
3. The production/deployment configuration is identified.
4. The CyberMedica adapter cannot simulate, cache, or override the Exochain outcome.
5. Tests prove positive, negative, unavailable, malformed, timeout, and cross-tenant cases.
6. Tests prove no raw sensitive content is anchored, logged, exported, or exposed through health/debug/telemetry.
7. The claim text maps to a receipt, decision, custody digest, or verified governance outcome.
8. The result is reviewed against the original CyberMedica PRD/context discipline.
