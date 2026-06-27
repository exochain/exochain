---
title: "Council Resolution CR-004: AVC Timestamp and Finality Authority"
status: ratified
created: 2026-06-21
ratified: 2026-06-21
tags: [council-resolution, avc, timestamp, finality, evidence, provenance]
links:
  - "[[CR-001-AEGIS-SYBIL-AUTHENTIC-PLURALITY]]"
  - "[[CR-002-AUTONOMOUS-RECURSIVE-IMPROVEMENT-INFRASTRUCTURE]]"
  - "[[CR-004-AVC-TIMESTAMP-FINALITY-COUNCIL-INPUT]]"
---
<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# Resolution of the EXOCHAIN Council on AVC Timestamp and Finality Authority

**Resolution ID:** CR-004
**Status:** RATIFIED -- Chair-directed adoption after council input recorded no veto
**Date:** 2026-06-21

---

## Section 1. Purpose

This Resolution decides the timestamp and finality authority model for Autonomous Volition Credential (AVC) trust receipts when EXOCHAIN makes civilizational-class, court-grade, or public reliance claims.

The purpose is to prevent three errors:

1. treating an internal node timestamp as independent time authority;
2. treating a local receipt link as full EXOCHAIN finality;
3. treating merged code or reachable health endpoints as production proof of civilizational-grade receipt evidence.

---

## Section 2. Council Input and Chair Rule

Council input was requested for CR-004 through the ExoForge 5-panel council-style triage process and recorded in `docs/council/CR-004-AVC-TIMESTAMP-FINALITY-COUNCIL-INPUT.md`.

The advisory review produced:

- Governance: approve with conditions.
- Legal: approve.
- Architecture: approve.
- Security: approve with conditions.
- Operations: approve.
- Tally: approved, score 0.465.
- Veto: none recorded.

The review method is advisory and not a claim that every human council member personally voted. The binding governance rule for this Resolution is the Chair directive from Bob Stewart: absent a member veto, the Resolution is completed; any member veto pauses activation and requires Chair intervention before production civilizational-class claims continue.

Because no veto was recorded in the available council input and the Chair directed completion, this Resolution is adopted as binding policy until amended or superseded by later Council action.

---

## Section 3. Binding Decision

The Council adopts a three-layer AVC timestamp and finality model.

### 3.1 Internal Protocol Evidence

An AVC trust receipt that is validator-signed, canonically encoded, action-bound, and hash-linked is valid internal EXOCHAIN protocol evidence.

Internal protocol evidence may prove:

- which validator signed the receipt;
- which credential and action commitment the receipt covers;
- which local receipt predecessor was linked;
- which timestamp provenance class was used.

Internal protocol evidence does not by itself prove external time, court-grade time, or independent finality.

### 3.2 EXOCHAIN Finality Evidence

Civilizational-class AVC receipts must be committed to an EXOCHAIN finality path before they are represented as more than internal protocol evidence.

An acceptable EXOCHAIN finality path must include at least one of:

- an `exo-dag` commit certificate or equivalent DAG-backed finality commitment;
- a BCTS lifecycle commitment that binds the receipt ID, action commitment, actor authority, and consent state;
- a council, gatekeeper, or operator finality approval that is independent of the requester and verified through existing EXOCHAIN authority-chain rules.

Requester self-approval is void. Gateway-generated hashes may prepare evidence, but final approval must come from an independent authority path.

### 3.3 External Timestamp or Anchor Evidence

Civilizational-class, court-grade, or public reliance claims require an independent external timestamp or anchor in addition to internal protocol evidence and EXOCHAIN finality evidence.

Acceptable external authorities include:

- an approved RFC 3161 timestamp authority;
- an approved eIDAS or equivalent qualified timestamp provider;
- an approved public-chain, notary, or institutional anchoring service;
- another external authority expressly approved by Council and recorded with the same verification standard.

The external authority record must identify:

- authority name and service type;
- authority DID;
- authority public key or certificate trust chain;
- endpoint or submission channel;
- canonical digest that was timestamped or anchored;
- verification procedure;
- timeout and retry policy;
- replay, duplicate, and idempotency handling;
- rollback or disablement path.

Postgres `clock_timestamp()` is operational timestamp provenance and database durability evidence. It is not independent external timestamp authority. A local Hybrid Logical Clock is deterministic causal ordering evidence. It is not independent external timestamp authority.

---

## Section 4. Evidence Classes

EXOCHAIN must label AVC receipt evidence according to the strongest completed evidence class.

| Evidence class | Minimum evidence | Permitted claim |
|----------------|------------------|-----------------|
| Internal protocol proof | Validator-signed AVC receipt with canonical action commitment and receipt linkage. | EXOCHAIN internal receipt evidence. |
| EXOCHAIN finality proof | Internal protocol proof plus DAG, BCTS, council, gatekeeper, or independent operator finality commitment. | Tamper-evident EXOCHAIN-governed receipt evidence. |
| Civilizational-class proof | EXOCHAIN finality proof plus independently verifiable external timestamp or anchor. | Court-grade or public reliance receipt evidence, subject to jurisdiction-specific legal review. |

No product, route, PR, deployment, dashboard, or adjacent surface may use a stronger claim than the evidence class it can verify at runtime.

---

## Section 5. Constitutional Basis

This Resolution preserves the eight constitutional invariants as follows:

- SeparationOfPowers: the requester cannot also be the finality authority for its own receipt.
- ConsentRequired: finality commitments must bind the consent state or the BCTS lifecycle that proves consent.
- NoSelfGrant: selecting a timestamp provider does not expand an actor's own permissions.
- HumanOverride: member veto and Chair intervention remain available before civilizational-class activation.
- KernelImmutability: the model does not mutate kernel configuration after initialization.
- AuthorityChainValid: timestamp and finality authorities require verifiable authority material.
- QuorumLegitimate: council or operator finality requires independent approval, not numerical theater.
- ProvenanceVerifiable: every evidence class must be independently reconstructible from signed, hashed, and canonical artifacts.

---

## Section 6. Operational Requirements

Production AVC receipt emission must fail closed when a deployment is configured to require civilizational-class proof but any required authority material is missing, malformed, expired, unreachable outside the permitted retry budget, or cryptographically unverifiable.

Production implementations must not:

- call `std::time::SystemTime::now()` or `Instant::now()` for governance receipt time;
- fabricate external timestamp or anchor evidence;
- accept requester-supplied finality as independent approval;
- downgrade failed external timestamp verification into success;
- disclose authority private keys, bootstrap tokens, database URLs, or raw secrets through health, status, debug, telemetry, or receipt responses.

Production activation must record the concrete authority configuration. If the implementation uses `EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL`, `EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID`, and `EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX`, all three must be present, non-empty, and verified before civilizational-class proof mode is active. The public-key variable may contain a comma-separated set of approved TSA signer SPKI DER hex pins when a provider uses multiple live signing keys behind one RFC 3161 endpoint. Deployments that set `EXO_AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY=true` must fail closed when the external timestamp authority is absent or unverifiable; deployments that leave that strict mode disabled may emit only internal or EXOCHAIN-finality receipt evidence and must not label it court-grade or public-reliance external time.

Provider selection does not require a new constitutional resolution when the provider satisfies this Resolution, the authority material is recorded, the test plan passes, and no member veto is recorded. A provider that changes the trust model, custody model, legal jurisdiction, or finality semantics requires renewed Council review.

### 6.1 Microsoft RFC 3161 Activation Record

The approved initial external timestamp authority for production strict AVC receipt emission is Microsoft Azure Artifact Signing's RFC 3161 timestamp service.

| Field | Value |
|-------|-------|
| Authority name | Microsoft Azure Artifact Signing RFC 3161 Timestamp Authority |
| Service type | RFC 3161 Time-Stamp Protocol over HTTP with CMS/X.509 TimeStampToken response |
| Endpoint | `http://timestamp.acs.microsoft.com` |
| Authority DID | `did:exo:microsoft-public-rsa-tsa` |
| Timestamp policy OID | `1.3.6.1.4.1.601.10.3.1` |
| Digest bound into RFC 3161 request | SHA-256 message imprint of canonical AVC evidence-subject bytes |
| EXOCHAIN commitment retained in receipt | Existing BLAKE3 `Hash256` evidence-subject hash |
| Production mode | `EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND=rfc3161` and `EXO_AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY=true` |
| HTTP timeout | 10 seconds per authority request |
| Retry behavior | No automatic retry inside receipt emission; callers or operators may retry the same AVC emission request, and receipt idempotency prevents duplicate divergent receipts. |
| Rotation behavior | Fail closed when the signer SPKI is absent from the pinned set until Council/operator authority material is updated and preflight passes. |
| Rollback path | Disable civilizational-class claims and unset strict external authority requirement, or redeploy with a newly approved authority record; do not silently relabel output as court-grade. |
| Entitlement context | Microsoft AI Partner / Azure benefits may cover account entitlement and cost controls; EXOCHAIN trust relies on cryptographic RFC 3161 verification, not partner status. |

Production strict configuration must set:

```text
EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND=rfc3161
EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL=http://timestamp.acs.microsoft.com
EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID=did:exo:microsoft-public-rsa-tsa
EXO_AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX=<comma-separated Microsoft TSA signer SPKI DER hex pin set from the preflight-verified production deployment guide>
EXO_AVC_RFC3161_TIMESTAMP_POLICY_OID=1.3.6.1.4.1.601.10.3.1
EXO_AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY=true
```

The preflight command is:

```bash
EXO_AVC_RFC3161_LIVE_PREFLIGHT=1 ./tools/avc_rfc3161_microsoft_preflight.sh
```

The June 27, 2026 preflights verified live Microsoft TimeStampTokens from the same endpoint with signer subjects `CN=Microsoft Public RSA Time Stamping Authority,OU=nShield TSS ESN:A500-05E0-D947,OU=Microsoft America Operations,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US` and `CN=Microsoft Public RSA Time Stamping Authority,OU=nShield TSS ESN:7A00-05E0-D947,OU=Microsoft America Operations,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US`. Production strict mode must pin the comma-separated set recorded in `docs/guides/production-deployment.md`; a signer outside that set fails closed.

---

## Section 7. Acceptance Standard

No deployment may claim civilizational-class AVC receipt proof until all acceptance criteria pass:

- validator-signed receipts include canonical action commitment evidence;
- receipt linkage rejects missing predecessors, branches, and disconnected chains;
- EXOCHAIN finality binds receipt ID, action commitment, actor authority, and consent state;
- external timestamp or anchor verification checks the exact canonical digest;
- authority DID and public key or certificate chain are verified before use;
- missing external authority configuration fails closed when civilizational-class external proof is required;
- invalid external authority signatures fail closed;
- timestamp replay, duplicate submission, and idempotency conflicts fail closed;
- production source guards prevent Rust system-time receipt shortcuts;
- deployment evidence proves the configured production service is using the selected authority material;
- rollback evidence proves the authority path can be disabled without silently downgrading civilizational-class claims into internal proof claims.

---

## Section 8. Issue and PR Interpretation

This Resolution provides the Council decision needed for the AVC receipt issue family:

- Issue #697 is fully satisfied only when AVC receipts are committed into an EXOCHAIN finality path and, for civilizational-class claims, externally anchored or timestamped.
- Issue #698 is fully satisfied only when an approved external or consensus timestamp authority is configured and verified.
- Issue #699 requires action commitments that are reconstructible from canonical action evidence.
- Issue #700 remains separate: database durability and redeploy continuity are required, but database durability is not external timestamp authority.
- PR #702 may be reviewed and merged as external timestamp code hardening if it satisfies the source and CI gates, but merge alone is not production civilizational-class activation.
- The CR-004 implementation branch extends PR #702 by committing configured AVC receipt emission to the shared `exo-dag` store as a deterministic `exo.avc.receipt.exochain_finality.v1` DAG node with a proving `TrustReceipt`, and by returning the finality hash, height, and finality receipt hash from `POST /api/v1/avc/receipts/emit`.
- Local implementation evidence satisfies the code-level EXOCHAIN finality hook for configured node runtime; production civilizational-class activation still requires human merge/deploy approval, authority configuration evidence, live or recorded external timestamp verification, and rollback evidence.

---

## Section 9. Validation Commands

The minimum validation package for code implementing this Resolution is:

```bash
cargo test -p exo-avc receipt -- --nocapture
cargo test -p exo-node avc -- --nocapture
cargo test -p exo-gateway dagdb --features production-db
rg -n "SystemTime::now|Instant::now" crates/exo-avc crates/exo-node crates/exo-gateway packages/exochain-wasm
git diff --check
```

When the external timestamp authority path is production-configured, the validation package must also include live or recorded-provider verification that checks a real authority response against the canonical receipt digest.

---

## Section 10. Ratification Effect

Upon adoption, CR-004 is the canonical Council interpretation of AVC timestamp and finality authority. It binds EXOCHAIN core, core runtime adapters, PR review, deployment status reports, issue closure criteria, adjacent-surface trust claims, and public receipt-evidence language.

This Resolution does not claim billing savings, thesis acceptance, public-route uptime, or production operational verification. Those claims require separate evidence matching the relevant runtime boundary.
