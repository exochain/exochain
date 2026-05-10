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

# Test Spec: 5-Panel Council Review

## Description
E2E verification of the `council-review.yaml` Syntaxis protocol. Simulates a T1+ proposal moving through the Decision Forum.

## Test Steps
1. **Initialize**: Trigger the protocol via a `protocol_call` event. Provide a mock `syntaxis_patch_proposal` payload.
2. **Execute `limitations-precheck`**: Verify the payload passes basic validation.
3. **Execute Panel Deliberation**: Simultaneously invoke the 5 panel nodes (`panel-gov`, `panel-legal`, `panel-arch`, `panel-sec`, `panel-ops`). Inject mock "Approve" votes for Gov, Legal, Arch, and Ops. Inject a mock "Reject" vote for Sec.
4. **Execute `aggregate-votes`**: Verify the consensus engine processes a 4/5 result.
5. **Execute `doctrine-triad-check`**: Verify the payload passes doctrine evaluation.
6. **Execute `constitutional-validation`**: Verify the invariant checker returns a clean receipt.
7. **Execute `resolution-generation`**: Trigger the ledger anchor.

## Expected Outputs
- The BCTS state must transition from `Deliberated` to `Verified` to `Governed`.
- The `aggregate_result` must show an Approved status because the 4/5 threshold (80%) was met despite the single rejection.
- The `dag_receipt` must be generated.

## Pass Criteria
The system correctly handles a split vote, enforces the confidence threshold, verifies the doctrine constraints, and successfully anchors the resolution to the DAG.