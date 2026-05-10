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

# Template: Evidence Schema

*Instructions for Artifact Builder: Define the exact data structures required for DAG anchoring to satisfy Transparency & Accountability.*

## 1. Immutability Requirements
*Define what must never be deleted or altered once written.*
- [e.g., All BCTS state transitions]
- [e.g., The cryptographic hash of all Council resolutions]

## 2. Schema Definitions
*Define the fields required for different transaction types.*

### Schema: standard_agent_action
- `timestamp`: ISO 8601
- `agent_id`: UUID
- `action_type`: String (e.g., "API_CALL", "DRAFT_COMPLETED")
- `policy_gates_passed`: Array of Gate IDs
- `context_hash`: SHA-256 of the prompt/data used

### Schema: human_override
- `timestamp`: ISO 8601
- `user_id`: UUID
- `override_type`: String (e.g., "HALT", "FORCE_APPROVE")
- `rationale`: String (Mandatory text input)
- `mfa_receipt`: String

## 3. Signing Format
*Specify the cryptographic signature requirements.*
- All agent actions must be signed by the agent's private key issued by `exo-gatekeeper`.
- All human overrides require an `ed25519` signature tied to the user's verified identity token.

## 4. Audit Retrieval Procedure
*How does a human retrieve this data?*
- [e.g., Using the `exo-dag-cli` tool, queried by date range and agent ID. Results output in JSON format.]

---
**Approval Block**
- Prepared by: `artifact-builder`
- Council Status: `[Draft / Governed]`
- CEO Signature: `[Pending]`