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

# Workflow: DAG Anchoring

This workflow defines how governance events, artifact approvals, and state transitions within the `gap/` incubator are immutably written to the ExoChain Directed Acyclic Graph (DAG) via the `exo-dag` crate.

## The Principle of Immutability
To satisfy the Transparency & Accountability invariant, no significant state change can exist solely in local memory. It must be anchored. If it is not on the DAG, it did not happen.

## What Gets Anchored
1. **Intake and Identity**: The CEO's initial cryptographic signature and verified mandate.
2. **BCTS Transitions**: Every time an artifact moves from `Draft` -> `Submitted` -> `Deliberated` -> `Governed` -> `Approved` -> `Executed`.
3. **Council Resolutions**: The individual votes of the 5 panels, their written rationale, and the final aggregate decision.
4. **Artifact Hashes**: When a GAP deliverable is finalized, the SHA-256 hash of the markdown file is anchored, not the raw text (to preserve privacy while ensuring tamper evidence).
5. **System Modifications**: Every patch deployed by the Self-Development team.

## Anchoring Procedure (The `ledger_anchor` node)
When a Syntaxis protocol hits a `ledger_anchor` node, the following procedure executes:

1. **Payload Assembly**: The node packages the required data. This includes the timestamp, the initiating agent/user ID, the target object ID (e.g., `authority-matrix-v1`), the new BCTS state, and the cryptographic signatures of all approvers.
2. **AI-IRB Formatting**: The payload is formatted according to the AI-IRB (Internal Review Board) schema required by `exo-dag`.
3. **Submission**: The payload is submitted to the local `exo-dag` instance via RPC.
4. **Verification**: The system waits for `exo-dag` to process the transaction, resolve the graph dependencies, and return a `dag_receipt` (which includes the transaction hash).
5. **State Finalization**: Only upon receiving a valid `dag_receipt` does the Syntaxis protocol officially mark the step as complete and move to the next node. If the DAG write fails, the workflow halts.