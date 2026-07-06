# LiveSafe Production Trust Activation Gates

## Source Basis

- `docs/EXOCHAIN_APP_BOUNDARY.md`
- `docs/TEST_PLAN.md`
- `docs/context/LIVESAFE_GENESIS_DEVELOPMENT_TRUST.md`
- `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md`
- `docs/context/LIVESAFE_TRUST_SIGNAL_VISUAL_LANGUAGE.md`
- `config/exochain-production-trust.json`
- `server/utils/exochain-production-trust-evidence.js`
- `server/utils/public-adapter-output-authorization.js`
- `server/utils/trust-status.js`
- `scripts/exochain-public-output-evidence-hash.mjs`
- `src/exochain-root-trust-state.ts`
- `src/exochain_adapter_activation.rs`
- `src/genesis-trust.ts`
- `src/trust-signal.ts`
- `tests/exochain-production-trust-evidence.test.ts`
- `tests/public-output-evidence-summary.test.ts`
- `tests/public-adapter-output-authorization.test.ts`
- `tests/exochain-root-trust-state.test.ts`
- `tests/public-exochain-copy-boundary.test.ts`
- `tests/exochain_adapter_activation.rs`
- `tests/genesis-trust.test.ts`
- `tests/trust-signal.test.ts`
- EXOCHAIN production probes on 2026-06-03:
  `https://exochain-production.up.railway.app/health`,
  `https://exochain-production.up.railway.app/ready`,
  `https://exochain-production.up.railway.app/api/v1/governance/status`,
  and `https://exochain-production.up.railway.app/api/v1/sentinels`.
- EXOCHAIN root-trust verifier command on 2026-06-03T21:24:50Z:
  `CARGO_TARGET_DIR=/tmp/exochain-origin-main-verify-target cargo run -p exo-node -- genesis verify-bundle --input <(jq '{bundle:.}' /Users/bobstewart/Documents/meshcore/exochain/artifacts/trust/avc-exo-ceremony-2026/root-trust-bundle.canonical.json)`
  from read-only `origin/main` worktree commit
  `379a45e1d9ab092ecd446d095a7b524570530efd`, returning
  `{"verified":true}`.

## Ground Truth

LiveSafe can develop internally during genesis, but public trust claims remain
inactive until every runtime and proof gate is satisfied by verified code,
tests, and documented evidence. This repo now has verified EXOCHAIN production
evidence for the AVC root-trust bundle, but it still lacks a wired LiveSafe
runtime adapter that would permit EXOCHAIN or root-backed public trust
signaling.

That means LiveSafe may describe the requirement for future verification, but it
must not present current customer-facing output as verified enforcement,
verified custody proof, verified consent proof, or verified root-backed trust.

The canonical public-output evidence summary hash is ceremony input only. It is
the deterministic `sha256:<hex>` material that AVC public adapter-output
authorization can bind to; it does not itself authorize public claims. The
summary builder requires explicit `asOf` input, verified EXOCHAIN production
evidence, verified EXOCHAIN connectivity, verified LiveSafe runtime-adapter
metadata, `public_claims_allowed: false` before authorization, and a
non-secret public metadata summary.

The controlling ladder is:

- `not_verified`: EXOCHAIN production evidence or LiveSafe adapter evidence is
  missing, blocked, or contradicted.
- `exochain_root_evidence_verified`: current read-only EXOCHAIN evidence proves
  root primitives exist and the EXOCHAIN production root-trust bundle verifies,
  but LiveSafe has not yet verified its adapter.
- `livesafe_adapter_verified`: LiveSafe has a verified adapter path, but public
  trust claims still remain blocked until production status proves the state.
- `public_trust_claims_allowed`: root evidence, LiveSafe adapter proof, and
  production trust-status proof all pass together.

## Current Contract Coverage

Current repo coverage establishes only the inactive, fail-closed posture:

- `src/exochain-root-trust-state.ts` and
  `tests/exochain-root-trust-state.test.ts` enforce that
  `exochain_root_evidence_verified` is a distinct intermediate state and does
  not imply `public_trust_claims_allowed`.
- `src/exochain_adapter_activation.rs` and
  `tests/exochain_adapter_activation.rs` prove activation must deny when the
  adapter is missing, malformed, rejected, timed out, unavailable, not-called,
  stale, revoked, contradicted, or carries raw sensitive payloads.
- `src/genesis-trust.ts` and `tests/genesis-trust.test.ts` enforce genesis
  development posture while keeping external trust signaling disabled until the
  7-of-13 FROST proof gate exists.
- `src/trust-signal.ts` and `tests/trust-signal.test.ts` keep trust-bearing UI
  in a visible not-yet-verified state and block verified-green output without
  proof-backed status.
- `server/utils/exochain-production-trust-evidence.js` and
  `tests/exochain-production-trust-evidence.test.ts` verify the
  source-backed EXOCHAIN production evidence bundle while carrying
  `production_sentinel_quorum_health_below_bft_minimum` as a non-blocking
  observation.
- `server/utils/exochain-production-trust-evidence.js`,
  `scripts/exochain-public-output-evidence-hash.mjs`, and
  `tests/public-output-evidence-summary.test.ts` define the canonical
  public-output evidence summary contract. The hash is SHA-256 over sorted-key
  canonical JSON, changes when required public evidence changes, rejects stale
  or malformed explicit timestamps, rejects missing or false production,
  EXOCHAIN connectivity, runtime-adapter, or pre-authorization public-claim
  evidence, and refuses secret or sensitive LiveSafe material.
- `server/utils/trust-status.js` and `tests/trust-status.test.ts` expose
  `exochain_production_evidence_state`, production health/readiness, root
  bundle, issuer, verifier, and observation fields while keeping
  `public_claims_allowed: false` until LiveSafe adapter proof also passes.
- `tests/public-exochain-copy-boundary.test.ts` blocks public UI and metadata
  copy that would claim active EXOCHAIN trust, bailment, audit, or sovereignty
  before adapter proof.
- `docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md` records that no
  verified LiveSafe runtime adapter path is wired today.

## Runtime And Proof Gates

| Gate | Required Evidence |
| --- | --- |
| Root workspace evidence exists | `crates/exo-root` is present in the EXOCHAIN workspace |
| Root ceremony policy exists | root genesis ceremony config and roster validation exist |
| FROST root profile | proof record for the 7-of-13 FROST keygen ceremony |
| Root bundle verification exists | root trust bundle verification function exists |
| Root signature verification exists | threshold signature verification path exists |
| EXOCHAIN production health | `https://exochain-production.up.railway.app/health` returns `status: ok` |
| EXOCHAIN production readiness | `https://exochain-production.up.railway.app/ready` returns `status: ok` |
| EXOCHAIN root-trust bundle verifier | EXOCHAIN verifier at commit `379a45e1d9ab092ecd446d095a7b524570530efd` returns `{"verified":true}` for bundle id `7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58` |
| Runtime adapter exists | route or library path invokes a verified EXOCHAIN adapter |
| Reject path | tests prove denial when EXOCHAIN rejects |
| Timeout path | tests prove denial when EXOCHAIN times out |
| Unavailable path | tests prove denial when EXOCHAIN is unavailable |
| Not-called path | tests prove denial when the adapter does not invoke EXOCHAIN |
| Stale path | tests prove denial when adapter proof or response state is stale |
| Revoked path | tests prove denial when adapter proof or authority state is revoked |
| Contradicted path | tests prove denial when adapter/runtime evidence contradicts permit state |
| Sensitive data boundary | tests prove raw sensitive records stay off-chain and out of anchors |
| Receipt boundary | tests prove receipts contain commitments, references, policy ids, and hashes only |
| Canonical public-output evidence hash | `npm run --silent evidence:public-output-hash -- --as-of <ISO-UTC>` emits one non-secret JSON record with `evidence_hash`, `algorithm`, `subject`, `audience`, `generated_from`, state, and reasons |
| External signal | rendered AVC badge, lock or shield symbol, color, glow, text, and machine-readable state |

## Current State

| Claim Area | State | Reason |
| --- | --- | --- |
| EXOCHAIN production/root evidence verified | `exochain_root_evidence_verified` | production `/health` and `/ready` returned `ok`; root-trust bundle id `7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58` verified at EXOCHAIN commit `379a45e1d9ab092ecd446d095a7b524570530efd`; read-only source evidence shows `crates/exo-root`, 7-of-13 ceremony policy, FROST DKG, root bundle verification, and root signature verification |
| LiveSafe adapter verified | inactive | no verified LiveSafe adapter path is wired |
| Public trust claims allowed | inactive | EXOCHAIN production evidence is verified, but LiveSafe adapter proof is still missing |
| Public-output evidence hash | ceremony evidence only | deterministic summary hash can be generated for AVC binding; the hash does not allow public claims without separate proof-bearing public adapter-output authorization |
| Production sentinel observation | non-blocking observation | `QuorumHealth` reports one validator, below BFT minimum; `Liveness` and `ReceiptIntegrity` are the required healthy sentinels for this LiveSafe production-evidence gate |
| Medical jacket custody proof | inactive | custody receipt adapter is not wired |
| Consent and revocation proof | inactive | consent adapter is not wired |
| P.A.C.E. recovery proof | inactive | VSS or recovery adapter is not wired |
| Onboarding/P.A.C.E. contract | implemented as adjacent Rust domain contract | synthetic contract only; no runtime enforcement claim |

## Required Public Display

Trust-bearing public output must keep inactive states visually obvious. The
not-verified state must display `THIS IS NOT YET VERIFIED`.

Any public surface that references trust state must preserve the inactive
warning, machine-readable status, and blocked verified treatment defined in
`docs/context/LIVESAFE_TRUST_SIGNAL_VISUAL_LANGUAGE.md`.

Public copy may state that EXOCHAIN production evidence is verified only when it
also states that LiveSafe public trust claims remain gated by adapter proof.
Until that adapter proof exists, public trust claims remain inactive.

## Disablement And Rollback

- Path classification: adjacent surface control document.
- Trust posture: EXOCHAIN production evidence verified; public trust claims
  remain inactive until LiveSafe runtime adapter and proof gates are verified.
- Data posture: documentation and synthetic contract references only; no raw
  sensitive data is introduced here.
- Disablement path: keep trust-bearing output on the inactive display state or
  remove the trust-bearing output from public surfaces. To rollback this slice,
  revert `config/exochain-production-trust.json`,
  `server/utils/exochain-production-trust-evidence.js`,
  `scripts/exochain-public-output-evidence-hash.mjs`, the trust-status
  production-evidence fields, and the public-copy wording changes; this returns
  LiveSafe to production-evidence-blocked status without enabling adapter
  claims or public-output hash generation.
