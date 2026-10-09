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

# Proposed JSON Schemas

**Status: PROPOSAL. Pending constitutional authorization. Not approved. Not a release.**

These schemas are interchange checks for a later implementation. Canonical
hashes use CBOR, not JSON. Integer fields are integers. Unknown properties
are rejected.

| Schema | Spec |
| --- | --- |
| `discovery-profile.schema.json` | `specs/MCP-A2A-DISCOVERY.md` |
| `bailment-negotiation.schema.json` | `specs/BAILMENT-NEGOTIATION.md` |
| `claim-attestation.schema.json` | `specs/CLAIM-ATTESTATION.md` |
| `x402-settlement.schema.json` | `specs/X402-SETTLEMENT.md` |
| `evidence-bundle.schema.json` | `specs/EVIDENCE-BUNDLE.md` |
| `financial-assurance.schema.json` | `specs/FINANCIAL-ASSURANCE.md` |
| `second-verifier-inputs.schema.json` | `TEST-PLAN.md` second-system input allowlist |
