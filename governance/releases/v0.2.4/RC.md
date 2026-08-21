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

# 0.2.4 release candidate

Narrow, honest RC. PDP decides. AVC records. x402 adapts.

This is **not** v0.3.0 evidence-grade closure. Issue #813 stays open.

## In scope

| Item | Status |
| --- | --- |
| PDP Allow / Deny / Challenge | In `main` via #818 |
| Bound payment-evidence hash; header is not paid | In `main` via #818 |
| AVC `payment_evidence_hash` on receipts; `validate_avc` unpaywalled | In `main` via #818 |
| crates.io `ml-dsa` default-features off (#812) | In tree; published only after this version ships |
| Two independent release environments (#789) | Workflow `approve` + `approve-second` |
| ExoChained contract re-pin (#811) | Toolkit PR against `e0e6dacf` |
| CGR reduction traces + combinator replay | Combinator/holon emit sealed traces; bundles carry them; MCP replays |
| RISC Zero CGR execution receipts | Guest + server prover; `ProofEnvelope::verify` calls `Receipt::verify` |

## Out of scope (still open)

| Item | Why it stays open |
| --- | --- |
| VCG-001 `ProductionReviewed` | External cryptographic review of the integration has not landed. Receipt verify is live; the registry label is not. |
| Groth16 receipt compression wrap | Default prover emits a zkVM execution receipt, not the on-chain Groth16 wrap. |
| #813 evidence-grade train | G00 / Art. 26 certification not claimed. |
| Signed tag + crates.io publish | Done: `v0.2.4` on `9ad6068a`; GitHub Release and 32 crates plus npm live. Yank of `0.2.3` is #822. |

## Publication sequence

1. Merge this RC branch after constitutional CI is green.
2. Create environments `release` (reviewer A) and `release-second` (reviewer B).
3. Sign and push `v0.2.4` from the merge commit.
4. Dispatch `EXOCHAIN Release` with `version=0.2.4` and `dry_run=false`.
5. Yank crates.io `0.2.3` after `0.2.4` is live (`ml-dsa`/`pkcs8` break).

Do not describe this RC as court-ready, Article 26 certified, or a 0.3.0 close.
CGR completeness here means sealed combinator replay plus an optional RISC Zero
execution receipt. It is not `AuditStatus::ProductionReviewed`.
