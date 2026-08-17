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

# v0.3.0 release goal

PDP decides. AVC records. x402 adapts. One stack. Then release.

## Architecture

| Layer | Owns | Does not own |
| --- | --- | --- |
| `exo-pdp` | Allow / Deny / Challenge under a signed mandate | Settlement, AVC credentials, x402 wire types |
| `exo-avc` | Credential, action signature, trust receipt (including `payment_evidence_hash`) | HTTP 402, payment facilitation |
| x402 adapter (`exo-pdp` `/x402/verify`) | Bound payment-evidence hash, 403/428/402/200, never-paywall list | Policy, receipts |

Facilitators call only `/x402/verify`. `POST /api/v1/avc/validate` stays free and does not mint 402. Header presence (`PAYMENT-SIGNATURE`) and caller booleans are never payment.

## Must be true before any tag

1. Missing payment on an otherwise permitted commercial mandate is `Challenge` (402), not `Deny` (403).
2. Deny still outranks a bound payment hash.
3. Payment evidence is a non-zero BLAKE3 hash of canonical CBOR. Zero hash and header-only proofs fail closed.
4. AVC receipts can record that hash without breaking legacy signing payloads.
5. `#812` — `exochain-core` builds from crates.io (`ml-dsa` without default `pkcs8`).
6. Open x402 PRs `#815` and `#816` are superseded by this stack, not merged as a second brain.
7. `#810` CGR traces stay out of this tag unless we claim spec §19.6.1.
8. `#789` two-person release approval remains a publication stop even after the code is green.

## Non-goals for this tag

AACP, CIM fiction, marketplace take-rate, LegalDyne branding, EXO Credits, Gamma, and a second evidence-pack product on AVC validate.

Tracks #813. Implements the durable split decided 2026-08-17.
